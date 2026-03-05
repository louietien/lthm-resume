from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import plotly.graph_objects as go
import plotly.io as pio


FILE_MAP = {
    "home": ("Home.md",),
    "home_work": ("Home  Work.md", "Home Work.md"),
    "work_home": ("Work Home.md", "Work  Home.md"),
    "work": ("Work.md",),
    "sleep": ("Sleep.md",),
}

IMPORT_SOURCE_ORDER = ["home", "home_work", "work_home", "work", "sleep"]
IMPORT_SOURCE_META = {
    "home": {"label": "Home", "header": "# Home"},
    "home_work": {"label": "Home -> Work", "header": "# Home > Work"},
    "work_home": {"label": "Work -> Home", "header": "# Work > Home"},
    "work": {"label": "Work", "header": "# Work"},
    "sleep": {"label": "Sleep", "header": "# Sleep"},
}
SOURCE_LABELS = {
    "home": "Home",
    "home_work": "To Work",
    "work_home": "To Home",
    "work": "Work",
    "sleep": "Sleep",
}

WINDOW_OPTIONS = {
    "30d": {"label": "30 Days", "days": 30},
    "90d": {"label": "90 Days", "days": 90},
    "180d": {"label": "180 Days", "days": 180},
    "all": {"label": "All Time", "days": None},
}

WEEKDAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
CONTRACT_MONTHLY_HOURS = 160.33
CONTRACT_DAILY_HOURS = 7.4

TIMESTAMP_PATTERN = re.compile(
    r"(?P<day>\d{2})[./](?P<month>\d{2})[./](?P<year>\d{4})(?:,\s*|\s+)(?P<hour>\d{2})[.:](?P<minute>\d{2})"
)


@dataclass(frozen=True)
class ParsedEvent:
    source: str
    event: str
    ts: datetime


def _parse_timestamp(raw: str) -> Optional[datetime]:
    match = TIMESTAMP_PATTERN.search(raw.strip())
    if not match:
        return None

    values = match.groupdict()
    return datetime(
        int(values["year"]),
        int(values["month"]),
        int(values["day"]),
        int(values["hour"]),
        int(values["minute"]),
    )


def _parse_event_line(raw_line: str) -> Optional[Tuple[str, datetime]]:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None
    if " at " not in line:
        return None

    event_text, stamp = line.rsplit(" at ", 1)
    ts = _parse_timestamp(stamp)
    if ts is None:
        return None

    cleaned = event_text.strip()
    if not cleaned:
        return None
    return cleaned, ts


def _iter_events(stats_dir: Path) -> Tuple[List[ParsedEvent], int]:
    events: List[ParsedEvent] = []
    parse_failures = 0

    for source, filenames in FILE_MAP.items():
        for filename in filenames:
            path = stats_dir / filename
            if not path.exists():
                continue

            for raw_line in path.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if " at " not in line:
                    # Ignore plain section labels like "Work > Home".
                    if TIMESTAMP_PATTERN.search(line) is None:
                        continue
                    parse_failures += 1
                    continue

                parsed = _parse_event_line(line)
                if parsed is None:
                    parse_failures += 1
                    continue

                event_text, ts = parsed
                events.append(ParsedEvent(source=source, event=event_text, ts=ts))

    deduped: List[ParsedEvent] = []
    seen = set()
    for event in sorted(events, key=lambda item: (item.ts, item.source, item.event)):
        key = (event.source, event.event, event.ts)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(event)

    return deduped, parse_failures


def sync_stats_sqlite(stats_dir: Path, conn: sqlite3.Connection) -> Dict[str, int]:
    events, parse_failures = _iter_events(stats_dir)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            event TEXT NOT NULL,
            ts TEXT NOT NULL,
            day TEXT NOT NULL,
            minute_of_day INTEGER NOT NULL
        )
        """
    )
    conn.execute("DELETE FROM events")

    conn.executemany(
        """
        INSERT INTO events (source, event, ts, day, minute_of_day)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (
                item.source,
                item.event,
                item.ts.strftime("%Y-%m-%d %H:%M:%S"),
                item.ts.strftime("%Y-%m-%d"),
                item.ts.hour * 60 + item.ts.minute,
            )
            for item in events
        ],
    )

    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source_event_day ON events(source, event, day)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_day ON events(day)")

    return {
        "event_count": len(events),
        "parse_failures": parse_failures,
    }


def get_import_options() -> List[Dict[str, str]]:
    options: List[Dict[str, str]] = []
    for key in IMPORT_SOURCE_ORDER:
        if key not in FILE_MAP:
            continue
        label = IMPORT_SOURCE_META.get(key, {}).get("label", key)
        options.append({"key": key, "label": label})
    return options


def import_plaintext_source(stats_dir: Path, source: str, payload: str) -> Dict[str, object]:
    if source not in FILE_MAP:
        raise ValueError("Unknown import source.")

    incoming: List[Tuple[str, datetime]] = []
    ignored_lines = 0
    for raw_line in payload.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parsed = _parse_event_line(line)
        if parsed is None:
            ignored_lines += 1
            continue
        incoming.append(parsed)

    if not incoming:
        raise ValueError("No parsable event lines found in import text.")

    existing: List[Tuple[str, datetime]] = []
    for filename in FILE_MAP[source]:
        path = stats_dir / filename
        if not path.exists():
            continue
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            parsed = _parse_event_line(raw_line)
            if parsed is not None:
                existing.append(parsed)

    merged: Dict[Tuple[str, datetime], Tuple[str, datetime]] = {}
    for event_text, ts in existing + incoming:
        merged[(event_text, ts)] = (event_text, ts)

    ordered = sorted(merged.values(), key=lambda item: (item[1], item[0]))
    header = IMPORT_SOURCE_META.get(source, {}).get("header", f"# {source}")
    lines = [header]
    lines.extend(f"{event_text} at {ts.strftime('%d/%m/%Y, %H.%M')}" for event_text, ts in ordered)

    stats_dir.mkdir(parents=True, exist_ok=True)
    target_path = stats_dir / FILE_MAP[source][0]
    target_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")

    return {
        "source": source,
        "target_file": target_path.name,
        "incoming_events": len(incoming),
        "existing_events": len(existing),
        "written_events": len(ordered),
        "ignored_lines": ignored_lines,
    }


def get_raw_source_options() -> List[Dict[str, str]]:
    options = [{"key": "all", "label": "All Sources"}]
    for key in IMPORT_SOURCE_ORDER:
        label = SOURCE_LABELS.get(key, IMPORT_SOURCE_META.get(key, {}).get("label", key))
        options.append({"key": key, "label": label})
    return options


def _coerce_raw_source(source: str) -> str:
    if source == "all":
        return source
    if source in SOURCE_LABELS:
        return source
    return "all"


def _coerce_raw_limit(value: object, default: int = 120) -> int:
    try:
        limit = int(value)
    except (TypeError, ValueError):
        return default
    if limit < 20:
        return 20
    if limit > 1000:
        return 1000
    return limit


def _coerce_raw_day(day: str) -> Optional[pd.Timestamp]:
    candidate = (day or "").strip()
    if not candidate:
        return None
    try:
        parsed = pd.to_datetime(candidate, format="%Y-%m-%d", errors="raise")
    except (ValueError, TypeError):
        return None
    return parsed.normalize()


def _build_raw_view_from_events(
    events: pd.DataFrame,
    source: str,
    day: Optional[pd.Timestamp],
    limit: int,
    window: str,
    window_start: Optional[pd.Timestamp],
) -> Dict[str, object]:
    filtered = events.copy()
    if window_start is not None:
        filtered = filtered[filtered["day"] >= window_start]
    if source != "all":
        filtered = filtered[filtered["source"] == source]
    if day is not None:
        filtered = filtered[filtered["day"] == day]

    total_filtered = int(len(filtered))
    latest_rows = filtered.sort_values("ts", ascending=False).head(limit)
    rows: List[Dict[str, str]] = []
    for _, row in latest_rows.iterrows():
        rows.append(
            {
                "timestamp": row["ts"].strftime("%Y-%m-%d %H:%M"),
                "date": row["day"].strftime("%Y-%m-%d"),
                "source_key": str(row["source"]),
                "source": SOURCE_LABELS.get(str(row["source"]), str(row["source"])),
                "event": str(row["event"]),
            }
        )

    count_by_source = filtered["source"].value_counts().to_dict() if not filtered.empty else {}
    return {
        "window": window,
        "window_start": window_start.strftime("%Y-%m-%d") if window_start is not None else "",
        "source": source,
        "day": day.strftime("%Y-%m-%d") if day is not None else "",
        "limit": int(limit),
        "total_rows": total_filtered,
        "returned_rows": len(rows),
        "rows": rows,
        "source_counts": {
            SOURCE_LABELS.get(str(key), str(key)): int(value) for key, value in count_by_source.items()
        },
        "source_options": get_raw_source_options(),
    }


def build_raw_events_data(
    stats_dir: Path,
    window: str = "90d",
    source: str = "all",
    day: str = "",
    limit: int = 120,
) -> Dict[str, object]:
    normalized_window = _coerce_window(window)
    normalized_source = _coerce_raw_source(source)
    normalized_day = _coerce_raw_day(day)
    normalized_limit = _coerce_raw_limit(limit)

    with sqlite3.connect(":memory:") as conn:
        sync_stats_sqlite(stats_dir=stats_dir, conn=conn)
        events = _read_events_frame(conn)

    if events.empty:
        return {
            "window": normalized_window,
            "window_start": "",
            "source": normalized_source,
            "day": normalized_day.strftime("%Y-%m-%d") if normalized_day is not None else "",
            "limit": normalized_limit,
            "total_rows": 0,
            "returned_rows": 0,
            "rows": [],
            "source_counts": {},
            "source_options": get_raw_source_options(),
        }

    max_day = events["day"].max().normalize()
    window_days = WINDOW_OPTIONS[normalized_window]["days"]
    window_start = None if window_days is None else max_day - pd.Timedelta(days=int(window_days) - 1)
    return _build_raw_view_from_events(
        events=events,
        source=normalized_source,
        day=normalized_day,
        limit=normalized_limit,
        window=normalized_window,
        window_start=window_start,
    )


def _read_events_frame(conn: sqlite3.Connection) -> pd.DataFrame:
    frame = pd.read_sql_query(
        "SELECT source, event, ts, day, minute_of_day FROM events ORDER BY ts",
        conn,
    )

    if frame.empty:
        return frame

    frame["ts"] = pd.to_datetime(frame["ts"])
    frame["day"] = pd.to_datetime(frame["day"])
    return frame


def _daily_stamp(frame: pd.DataFrame, source: str, event: str, agg: str) -> pd.Series:
    subset = frame[(frame["source"] == source) & (frame["event"] == event)]
    if subset.empty:
        return pd.Series(dtype="datetime64[ns]")

    grouped = subset.groupby("day")["ts"]
    if agg == "min":
        return grouped.min()
    return grouped.max()


def _duration_series(
    start_series: pd.Series,
    end_series: pd.Series,
    min_minutes: int,
    max_minutes: int,
) -> pd.Series:
    merged = pd.concat([start_series.rename("start"), end_series.rename("end")], axis=1).dropna()
    if merged.empty:
        return pd.Series(dtype="timedelta64[ns]")

    duration = merged["end"] - merged["start"]
    min_delta = pd.Timedelta(minutes=min_minutes)
    max_delta = pd.Timedelta(minutes=max_minutes)
    return duration[(duration >= min_delta) & (duration <= max_delta)]


def _series_to_minutes(series: pd.Series) -> pd.Series:
    return series.dt.total_seconds() / 60.0


def _series_to_hours(series: pd.Series) -> pd.Series:
    return series.dt.total_seconds() / 3600.0


def _series_to_clock_minutes(series: pd.Series) -> pd.Series:
    if series.empty:
        return pd.Series(dtype="float64")
    values = (series.dt.hour * 60 + series.dt.minute).astype(float)
    values.index = series.index
    return values


def _safe_mean(series: pd.Series) -> Optional[float]:
    if series.empty:
        return None
    value = series.mean()
    if pd.isna(value):
        return None
    return float(value)


def _safe_median(series: pd.Series) -> Optional[float]:
    if series.empty:
        return None
    value = series.median()
    if pd.isna(value):
        return None
    return float(value)


def _safe_std(series: pd.Series) -> Optional[float]:
    if series.empty:
        return None
    value = series.std(ddof=0)
    if pd.isna(value):
        return None
    return float(value)


def _safe_min(series: pd.Series) -> Optional[float]:
    if series.empty:
        return None
    value = series.min()
    if pd.isna(value):
        return None
    return float(value)


def _safe_max(series: pd.Series) -> Optional[float]:
    if series.empty:
        return None
    value = series.max()
    if pd.isna(value):
        return None
    return float(value)


def _format_minutes(value: Optional[float]) -> str:
    if value is None or pd.isna(value):
        return "-"
    return "{0:.0f} min".format(value)


def _format_hours(value: Optional[float]) -> str:
    if value is None or pd.isna(value):
        return "-"
    hours = int(value)
    minutes = int(round((value - hours) * 60))
    if minutes == 60:
        hours += 1
        minutes = 0
    return "{0}h {1:02d}m".format(hours, minutes)


def _format_clock(minutes_value: Optional[float]) -> str:
    if minutes_value is None or pd.isna(minutes_value):
        return "-"
    minute_total = int(round(minutes_value)) % (24 * 60)
    hour, minute = divmod(minute_total, 60)
    return "{0:02d}:{1:02d}".format(hour, minute)


def _clock_series(series: pd.Series) -> pd.Series:
    if series.empty:
        return pd.Series(dtype="object")
    return series.apply(lambda value: _format_clock(float(value)) if pd.notna(value) else "-")


def _format_percent(value: Optional[float]) -> str:
    if value is None or pd.isna(value):
        return "-"
    return "{0:.0f}%".format(value)


def _format_signed_minutes(value: Optional[float]) -> str:
    if value is None or pd.isna(value):
        return "-"
    return "{0:+.0f} min".format(value)


def _format_decimal_hours(value: Optional[float], decimals: int = 1) -> str:
    if value is None or pd.isna(value):
        return "-"
    return "{0:.{1}f}h".format(value, decimals)


def _clamp_percent(value: Optional[float]) -> float:
    if value is None or pd.isna(value):
        return 0.0
    if value < 0:
        return 0.0
    if value > 100:
        return 100.0
    return float(value)


def _coerce_window(window: str) -> str:
    if window in WINDOW_OPTIONS:
        return window
    return "90d"


def _apply_window(series: pd.Series, start_day: Optional[pd.Timestamp]) -> pd.Series:
    if start_day is None or series.empty:
        return series
    return series[series.index >= start_day]


def _clock_ticks(start_minute: int, end_minute: int, step: int = 60) -> Tuple[List[int], List[str]]:
    tickvals = list(range(start_minute, end_minute + 1, step))
    ticktext = ["{0:02d}:00".format((value // 60) % 24) for value in tickvals]
    return tickvals, ticktext


def _figure_to_html(fig: go.Figure) -> str:
    return pio.to_html(
        fig,
        full_html=False,
        include_plotlyjs=False,
        config={
            "displayModeBar": False,
            "responsive": True,
            "scrollZoom": False,
        },
    )


def _empty_chart(title: str, subtitle: str) -> str:
    fig = go.Figure()
    fig.update_layout(
        title={"text": "{0}<br><sup>{1}</sup>".format(title, subtitle), "x": 0.01, "y": 0.94},
        margin={"l": 26, "r": 20, "t": 84, "b": 24},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis={"visible": False},
        yaxis={"visible": False},
        annotations=[
            {
                "text": "Not enough data in selected window",
                "showarrow": False,
                "x": 0.5,
                "y": 0.5,
                "xref": "paper",
                "yref": "paper",
                "font": {"size": 14},
            }
        ],
    )
    return _figure_to_html(fig)


def _weekday_single_frame(series: pd.Series) -> pd.DataFrame:
    frame = pd.DataFrame(index=range(7))
    frame["label"] = WEEKDAY_LABELS

    if series.empty:
        frame["mean"] = pd.NA
        frame["median"] = pd.NA
        frame["count"] = pd.NA
        return frame

    grouped = pd.DataFrame({"value": series})
    grouped["weekday"] = grouped.index.weekday
    agg = grouped.groupby("weekday")["value"].agg(["mean", "median", "count"])
    agg = agg.reindex(range(7))

    frame["mean"] = agg["mean"]
    frame["median"] = agg["median"]
    frame["count"] = agg["count"]
    return frame


def _weekday_dual_frame(series_a: pd.Series, series_b: pd.Series) -> pd.DataFrame:
    frame = pd.DataFrame(index=range(7))
    frame["label"] = WEEKDAY_LABELS

    a = _weekday_single_frame(series_a)
    b = _weekday_single_frame(series_b)

    frame["mean_a"] = a["mean"]
    frame["count_a"] = a["count"]
    frame["mean_b"] = b["mean"]
    frame["count_b"] = b["count"]
    return frame


def _build_commute_duration_chart(commute_to_minutes: pd.Series, commute_from_minutes: pd.Series) -> str:
    frame = pd.concat(
        [
            commute_to_minutes.rename("To work"),
            commute_from_minutes.rename("Homebound"),
        ],
        axis=1,
    ).sort_index()

    if frame.dropna(how="all").empty:
        return _empty_chart("Commute Duration", "Morning and evening trip duration")

    fig = go.Figure()
    if frame["To work"].notna().any():
        fig.add_trace(
            go.Scatter(
                x=frame.index,
                y=frame["To work"],
                mode="lines+markers",
                name="To work",
                line={"width": 2.6, "color": "#e66f3a"},
                marker={"size": 6},
            )
        )

    if frame["Homebound"].notna().any():
        fig.add_trace(
            go.Scatter(
                x=frame.index,
                y=frame["Homebound"],
                mode="lines+markers",
                name="Homebound",
                line={"width": 2.6, "color": "#2f7ac2"},
                marker={"size": 6},
            )
        )

    fig.update_layout(
        title={"text": "Commute Duration", "x": 0.01, "y": 0.95},
        margin={"l": 40, "r": 18, "t": 86, "b": 90},
        hovermode="x unified",
        legend={"orientation": "h", "x": 0.0, "xanchor": "left", "y": -0.22, "yanchor": "top"},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        yaxis={"title": "Minutes", "rangemode": "tozero", "gridcolor": "rgba(90,100,120,0.2)"},
        xaxis={"title": "Date", "gridcolor": "rgba(90,100,120,0.12)"},
    )

    return _figure_to_html(fig)


def _build_work_hours_chart(workday_hours: pd.Series, out_of_home_hours: pd.Series) -> str:
    work_monthly = workday_hours.resample("MS").mean() if not workday_hours.empty else pd.Series(dtype="float64")
    out_monthly = (
        out_of_home_hours.resample("MS").mean() if not out_of_home_hours.empty else pd.Series(dtype="float64")
    )

    monthly = pd.concat([work_monthly.rename("At work"), out_monthly.rename("Out of home")], axis=1).dropna(how="all")

    if monthly.empty:
        return _empty_chart("Work and Out-of-Home Hours", "Monthly average daily hours")

    fig = go.Figure()
    if monthly["At work"].notna().any():
        fig.add_trace(
            go.Bar(
                x=monthly.index,
                y=monthly["At work"],
                name="At work",
                marker={"color": "#f08d25"},
            )
        )

    if monthly["Out of home"].notna().any():
        fig.add_trace(
            go.Bar(
                x=monthly.index,
                y=monthly["Out of home"],
                name="Out of home",
                marker={"color": "#566ce8"},
            )
        )

    fig.update_layout(
        title={"text": "Work and Out-of-Home Hours", "x": 0.01, "y": 0.95},
        margin={"l": 40, "r": 18, "t": 86, "b": 90},
        barmode="group",
        hovermode="x unified",
        legend={"orientation": "h", "x": 0.0, "xanchor": "left", "y": -0.22, "yanchor": "top"},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        yaxis={"title": "Hours", "rangemode": "tozero", "gridcolor": "rgba(90,100,120,0.2)"},
        xaxis={"title": "Month", "gridcolor": "rgba(90,100,120,0.12)"},
    )

    return _figure_to_html(fig)


def _build_sleep_trend_chart(bedtime_minutes: pd.Series) -> str:
    if bedtime_minutes.empty:
        return _empty_chart("Bedtime Trend", "Inferred from first phone charge event")

    rolling = bedtime_minutes.rolling(window=14, min_periods=4).mean()
    bedtime_clock = _clock_series(bedtime_minutes)
    rolling_valid = rolling.dropna()
    rolling_clock = _clock_series(rolling_valid)

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=bedtime_minutes.index,
            y=bedtime_minutes,
            customdata=bedtime_clock,
            mode="markers",
            name="Bedtime points",
            marker={"size": 7, "color": "#1f9b84", "opacity": 0.72},
            hovertemplate="Date: %{x|%Y-%m-%d}<br>Bedtime: %{customdata}<extra></extra>",
        )
    )

    if not rolling_valid.empty:
        fig.add_trace(
            go.Scatter(
                x=rolling_valid.index,
                y=rolling_valid,
                customdata=rolling_clock,
                mode="lines",
                name="14-day trend",
                line={"width": 2.5, "color": "#da4f7a"},
                hovertemplate="Date: %{x|%Y-%m-%d}<br>14-day trend: %{customdata}<extra></extra>",
            )
        )

    ticks, labels = _clock_ticks(21 * 60, 30 * 60, 60)

    fig.update_layout(
        title={"text": "Bedtime Trend", "x": 0.01, "y": 0.95},
        margin={"l": 40, "r": 18, "t": 86, "b": 90},
        hovermode="x unified",
        legend={"orientation": "h", "x": 0.0, "xanchor": "left", "y": -0.22, "yanchor": "top"},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        yaxis={
            "title": "Clock time",
            "tickmode": "array",
            "tickvals": ticks,
            "ticktext": labels,
            "range": [20.5 * 60, 30.3 * 60],
            "gridcolor": "rgba(90,100,120,0.2)",
        },
        xaxis={"title": "Date", "gridcolor": "rgba(90,100,120,0.12)"},
    )

    return _figure_to_html(fig)


def _build_weekday_dual_bar(
    frame: pd.DataFrame,
    title: str,
    subtitle: str,
    y_title: str,
    label_a: str,
    label_b: str,
) -> str:
    if frame[["mean_a", "mean_b"]].dropna(how="all").empty:
        return _empty_chart(title, subtitle)

    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            x=frame["label"],
            y=frame["mean_a"],
            name=label_a,
            marker={"color": "#d96e43"},
        )
    )
    fig.add_trace(
        go.Bar(
            x=frame["label"],
            y=frame["mean_b"],
            name=label_b,
            marker={"color": "#4f86d8"},
        )
    )

    fig.update_layout(
        title={"text": "{0}<br><sup>{1}</sup>".format(title, subtitle), "x": 0.01, "y": 0.95},
        margin={"l": 40, "r": 18, "t": 96, "b": 90},
        barmode="group",
        hovermode="x unified",
        legend={"orientation": "h", "x": 0.0, "xanchor": "left", "y": -0.22, "yanchor": "top"},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        yaxis={"title": y_title, "rangemode": "tozero", "gridcolor": "rgba(90,100,120,0.2)"},
        xaxis={"title": "Weekday", "categoryorder": "array", "categoryarray": WEEKDAY_LABELS},
    )

    return _figure_to_html(fig)


def _build_weekday_single_bar(
    frame: pd.DataFrame,
    title: str,
    subtitle: str,
    y_title: str,
    clock_axis: bool,
) -> str:
    if frame[["mean"]].dropna(how="all").empty:
        return _empty_chart(title, subtitle)

    if clock_axis:
        customdata = frame["mean"].apply(lambda value: _format_clock(value) if pd.notna(value) else "-")
        hovertemplate = "Weekday: %{x}<br>Average: %{customdata}<extra></extra>"
    else:
        customdata = frame["mean"]
        hovertemplate = "Weekday: %{x}<br>Average: %{y:.2f}<extra></extra>"

    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            x=frame["label"],
            y=frame["mean"],
            customdata=customdata,
            name="Average",
            marker={"color": "#2f9d8a"},
            hovertemplate=hovertemplate,
        )
    )

    yaxis: Dict[str, object] = {
        "title": y_title,
        "gridcolor": "rgba(90,100,120,0.2)",
    }
    if clock_axis:
        ticks, labels = _clock_ticks(21 * 60, 30 * 60, 60)
        yaxis["tickmode"] = "array"
        yaxis["tickvals"] = ticks
        yaxis["ticktext"] = labels
        yaxis["range"] = [20.5 * 60, 30.3 * 60]
    else:
        yaxis["rangemode"] = "tozero"

    fig.update_layout(
        title={"text": "{0}<br><sup>{1}</sup>".format(title, subtitle), "x": 0.01, "y": 0.95},
        margin={"l": 40, "r": 18, "t": 96, "b": 70},
        showlegend=False,
        hovermode="x unified",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        yaxis=yaxis,
        xaxis={"title": "Weekday", "categoryorder": "array", "categoryarray": WEEKDAY_LABELS},
    )

    return _figure_to_html(fig)


def _build_clock_timeline_chart(
    series_map: Dict[str, pd.Series],
    title: str,
    subtitle: str,
    y_min: int,
    y_max: int,
) -> str:
    has_data = any(not series.empty for series in series_map.values())
    if not has_data:
        return _empty_chart(title, subtitle)

    colors = ["#db7547", "#4e8bd8", "#8c62d8", "#22a48b"]
    fig = go.Figure()

    for index, (label, series) in enumerate(series_map.items()):
        if series.empty:
            continue
        clock_labels = _clock_series(series)
        fig.add_trace(
            go.Scatter(
                x=series.index,
                y=series,
                customdata=clock_labels,
                mode="lines+markers",
                name=label,
                line={"width": 2.0, "color": colors[index % len(colors)]},
                marker={"size": 5},
                hovertemplate="Date: %{x|%Y-%m-%d}<br>"
                + label
                + ": %{customdata}<extra></extra>",
            )
        )

    ticks, labels = _clock_ticks(y_min, y_max, 60)

    fig.update_layout(
        title={"text": "{0}<br><sup>{1}</sup>".format(title, subtitle), "x": 0.01, "y": 0.95},
        margin={"l": 40, "r": 18, "t": 96, "b": 90},
        hovermode="x unified",
        legend={"orientation": "h", "x": 0.0, "xanchor": "left", "y": -0.22, "yanchor": "top"},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        yaxis={
            "title": "Clock time",
            "tickmode": "array",
            "tickvals": ticks,
            "ticktext": labels,
            "range": [y_min - 20, y_max + 20],
            "gridcolor": "rgba(90,100,120,0.2)",
        },
        xaxis={"title": "Date", "gridcolor": "rgba(90,100,120,0.12)"},
    )

    return _figure_to_html(fig)


def _build_bedtime_distribution_chart(bedtime_series: pd.Series) -> str:
    if bedtime_series.empty:
        return _empty_chart("Bedtime Distribution", "How often each bedtime range appears")

    fig = go.Figure()
    fig.add_trace(
        go.Histogram(
            x=bedtime_series,
            name="Nights",
            xbins={"size": 20},
            marker={"color": "#5a8de1", "line": {"color": "#2f4e9b", "width": 0.6}},
            opacity=0.9,
        )
    )

    ticks, labels = _clock_ticks(21 * 60, 30 * 60, 60)

    fig.update_layout(
        title={"text": "Bedtime Distribution", "x": 0.01, "y": 0.95},
        margin={"l": 40, "r": 18, "t": 86, "b": 70},
        showlegend=False,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis={"title": "Bedtime", "tickmode": "array", "tickvals": ticks, "ticktext": labels},
        yaxis={"title": "Count", "rangemode": "tozero", "gridcolor": "rgba(90,100,120,0.2)"},
        bargap=0.06,
    )

    return _figure_to_html(fig)


def _build_commute_rows(commute_to_minutes: pd.Series, commute_from_minutes: pd.Series) -> List[Dict[str, str]]:
    merged = pd.concat([commute_to_minutes.rename("to_work"), commute_from_minutes.rename("to_home")], axis=1)
    merged = merged.sort_index(ascending=False)

    rows: List[Dict[str, str]] = []
    for day, row in merged.head(12).iterrows():
        rows.append(
            {
                "date": day.strftime("%Y-%m-%d"),
                "to_work": _format_minutes(row["to_work"]),
                "to_home": _format_minutes(row["to_home"]),
            }
        )
    return rows


def _build_work_rows(workday_hours: pd.Series, out_of_home_hours: pd.Series) -> List[Dict[str, str]]:
    merged = pd.concat([workday_hours.rename("workday"), out_of_home_hours.rename("out_of_home")], axis=1)
    merged = merged.sort_index(ascending=False)

    rows: List[Dict[str, str]] = []
    for day, row in merged.head(12).iterrows():
        rows.append(
            {
                "date": day.strftime("%Y-%m-%d"),
                "workday": _format_hours(row["workday"]),
                "out_of_home": _format_hours(row["out_of_home"]),
            }
        )
    return rows


def _build_sleep_rows(bedtime_series: pd.Series) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for day, value in bedtime_series.sort_index(ascending=False).head(12).items():
        rows.append(
            {
                "date": day.strftime("%Y-%m-%d"),
                "bedtime": _format_clock(float(value)),
            }
        )
    return rows


def _build_commute_weekday_rows(weekday_frame: pd.DataFrame) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for _, row in weekday_frame.iterrows():
        rows.append(
            {
                "weekday": row["label"],
                "to_work": _format_minutes(row["mean_a"]),
                "to_home": _format_minutes(row["mean_b"]),
                "mornings": "{0}".format(int(row["count_a"])) if pd.notna(row["count_a"]) else "0",
                "evenings": "{0}".format(int(row["count_b"])) if pd.notna(row["count_b"]) else "0",
            }
        )
    return rows


def _build_work_weekday_rows(weekday_frame: pd.DataFrame) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for _, row in weekday_frame.iterrows():
        rows.append(
            {
                "weekday": row["label"],
                "workday": _format_hours(row["mean_a"]),
                "out_of_home": _format_hours(row["mean_b"]),
                "days": "{0}".format(int(row["count_a"])) if pd.notna(row["count_a"]) else "0",
            }
        )
    return rows


def _build_sleep_weekday_rows(weekday_frame: pd.DataFrame) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for _, row in weekday_frame.iterrows():
        rows.append(
            {
                "weekday": row["label"],
                "bedtime": _format_clock(row["mean"]),
                "nights": "{0}".format(int(row["count"])) if pd.notna(row["count"]) else "0",
            }
        )
    return rows


def _build_timeline_rows(events: pd.DataFrame) -> List[Dict[str, str]]:
    if events.empty:
        return []

    recent = events.sort_values("ts", ascending=False).head(22)
    rows: List[Dict[str, str]] = []
    for _, row in recent.iterrows():
        rows.append(
            {
                "timestamp": row["ts"].strftime("%Y-%m-%d %H:%M"),
                "source": SOURCE_LABELS.get(str(row["source"]), str(row["source"])),
                "event": str(row["event"]),
            }
        )
    return rows


def _percent_before_threshold(series: pd.Series, threshold: float) -> Optional[float]:
    if series.empty:
        return None
    return float((series <= threshold).mean() * 100.0)


def _build_contract_tracking(
    workday_all_hours: pd.Series,
    latest_day: pd.Timestamp,
) -> Dict[str, object]:
    month_start = latest_day.replace(day=1)
    month_end = (month_start + pd.offsets.MonthEnd(1)).normalize()
    month_label = latest_day.strftime("%B %Y")

    month_hours = workday_all_hours[(workday_all_hours.index >= month_start) & (workday_all_hours.index <= month_end)]
    actual_hours = float(month_hours.sum()) if not month_hours.empty else 0.0

    target_hours = float(CONTRACT_MONTHLY_HOURS)
    progress_pct = (actual_hours / target_hours * 100.0) if target_hours > 0 else 0.0

    business_days_elapsed = len(pd.bdate_range(month_start, latest_day))
    expected_to_date = business_days_elapsed * float(CONTRACT_DAILY_HOURS)
    pace_pct = (actual_hours / expected_to_date * 100.0) if expected_to_date > 0 else 0.0

    next_day = latest_day + pd.Timedelta(days=1)
    remaining_business_days = len(pd.bdate_range(next_day, month_end))
    remaining_hours = max(target_hours - actual_hours, 0.0)
    needed_per_day = (remaining_hours / remaining_business_days) if remaining_business_days > 0 else 0.0

    elapsed_daily_average = (actual_hours / business_days_elapsed) if business_days_elapsed > 0 else 0.0
    projected_month_end = actual_hours + (remaining_business_days * elapsed_daily_average)

    return {
        "month_label": month_label,
        "as_of": latest_day.strftime("%Y-%m-%d"),
        "target_hours": target_hours,
        "daily_target_hours": float(CONTRACT_DAILY_HOURS),
        "actual_hours": actual_hours,
        "expected_to_date_hours": expected_to_date,
        "remaining_hours": remaining_hours,
        "remaining_business_days": int(remaining_business_days),
        "needed_per_day_hours": needed_per_day,
        "projected_month_end_hours": projected_month_end,
        "completion_pct": progress_pct,
        "pace_pct": pace_pct,
        "completion_pct_clamped": _clamp_percent(progress_pct),
        "pace_pct_clamped": _clamp_percent(pace_pct),
        "on_track": actual_hours >= expected_to_date if expected_to_date > 0 else True,
    }


def _build_contract_history_rows(workday_all_hours: pd.Series, latest_day: pd.Timestamp) -> List[Dict[str, object]]:
    if workday_all_hours.empty:
        return []

    month_totals = workday_all_hours.groupby(workday_all_hours.index.to_period("M")).sum().sort_index()
    month_totals = month_totals.tail(8)

    rows: List[Dict[str, object]] = []
    for period, total in month_totals.items():
        month_ts = period.to_timestamp()
        month_end = (month_ts + pd.offsets.MonthEnd(1)).normalize()
        is_current = month_ts.year == latest_day.year and month_ts.month == latest_day.month
        target = float(CONTRACT_MONTHLY_HOURS)
        pct = (float(total) / target * 100.0) if target > 0 else 0.0
        status = "hit"
        if pct < 100:
            status = "miss"
        if is_current:
            status = "active"

        rows.append(
            {
                "month": month_ts.strftime("%b %Y"),
                "actual_hours": float(total),
                "target_hours": target,
                "pct": pct,
                "pct_clamped": _clamp_percent(pct),
                "is_current": is_current,
                "status": status,
                "range_end": month_end.strftime("%Y-%m-%d"),
            }
        )

    rows.reverse()
    return rows


def build_dashboard_data(stats_dir: Path, window: str = "90d") -> Dict[str, object]:
    normalized_window = _coerce_window(window)
    with sqlite3.connect(":memory:") as conn:
        ingest_info = sync_stats_sqlite(stats_dir=stats_dir, conn=conn)
        events = _read_events_frame(conn)

    if events.empty:
        return {
            "window": normalized_window,
            "window_options": WINDOW_OPTIONS,
            "summary_cards": [{"label": "Events loaded", "value": "0", "meta": "No stats data found"}],
            "coverage": "No data",
            "timeline_rows": [],
            "raw": {
                "window": normalized_window,
                "window_start": "",
                "source": "all",
                "day": "",
                "limit": 120,
                "total_rows": 0,
                "returned_rows": 0,
                "rows": [],
                "source_counts": {},
                "source_options": get_raw_source_options(),
            },
            "commute": {
                "metrics": [],
                "insights": ["No parsable commute events found."],
                "plot_main": _empty_chart("Commute Duration", "Morning and evening trip duration"),
                "plot_weekday": _empty_chart("Commute by Weekday", "Average commute minutes by weekday"),
                "plot_timeline": _empty_chart("Commute Timeline", "Clock-time pattern across days"),
                "rows": [],
                "weekday_rows": [],
            },
            "work": {
                "metrics": [],
                "insights": ["No parsable work events found."],
                "plot_main": _empty_chart("Work and Out-of-Home Hours", "Monthly average daily hours"),
                "plot_weekday": _empty_chart("Work by Weekday", "Average hours by weekday"),
                "plot_timeline": _empty_chart("Workday Timeline", "Arrival and departure clock-time pattern"),
                "rows": [],
                "weekday_rows": [],
                "contract_progress": {
                    "month_label": "-",
                    "as_of": "-",
                    "target_hours": float(CONTRACT_MONTHLY_HOURS),
                    "daily_target_hours": float(CONTRACT_DAILY_HOURS),
                    "actual_hours": 0.0,
                    "expected_to_date_hours": 0.0,
                    "remaining_hours": 0.0,
                    "remaining_business_days": 0,
                    "needed_per_day_hours": 0.0,
                    "projected_month_end_hours": 0.0,
                    "completion_pct": 0.0,
                    "pace_pct": 0.0,
                    "completion_pct_clamped": 0.0,
                    "pace_pct_clamped": 0.0,
                    "on_track": False,
                },
                "contract_history_rows": [],
            },
            "sleep": {
                "metrics": [],
                "insights": ["No parsable sleep proxy events found."],
                "plot_main": _empty_chart("Bedtime Trend", "Inferred from first phone charge event"),
                "plot_weekday": _empty_chart("Bedtime by Weekday", "Average bedtime by weekday"),
                "plot_distribution": _empty_chart("Bedtime Distribution", "How often each bedtime range appears"),
                "rows": [],
                "weekday_rows": [],
            },
        }

    max_day = events["day"].max().normalize()
    min_day = events["day"].min().normalize()
    window_days = WINDOW_OPTIONS[normalized_window]["days"]
    window_start = None if window_days is None else max_day - pd.Timedelta(days=int(window_days) - 1)

    left_home_hw = _daily_stamp(events, "home_work", "Left home", "min")
    arrive_work_hw = _daily_stamp(events, "home_work", "Arrived at work", "min")
    commute_to = _duration_series(left_home_hw, arrive_work_hw, min_minutes=5, max_minutes=180)

    arrive_work = _daily_stamp(events, "work", "Arrived at work", "min")
    left_work = _daily_stamp(events, "work", "Left work", "max")
    workday = _duration_series(arrive_work, left_work, min_minutes=180, max_minutes=720)

    left_home = _daily_stamp(events, "home", "Left home", "min")
    arrive_home = _daily_stamp(events, "home", "Arrived at home", "max")
    # Prefer dedicated work->home commute stamps when present, fall back to work/home logs otherwise.
    left_work_wh = _daily_stamp(events, "work_home", "Left work", "min")
    arrive_home_wh = _daily_stamp(events, "work_home", "Arrived at home", "max")
    commute_from_direct = _duration_series(left_work_wh, arrive_home_wh, min_minutes=5, max_minutes=300)
    commute_from_fallback = _duration_series(left_work, arrive_home, min_minutes=5, max_minutes=300)
    commute_from = commute_from_direct.combine_first(commute_from_fallback)
    out_of_home = _duration_series(left_home, arrive_home, min_minutes=180, max_minutes=1200)

    workday_all_hours = _series_to_hours(workday)

    sleep_events = events[(events["source"] == "sleep") & (events["event"] == "Set phone to charge")].copy()
    if sleep_events.empty:
        bedtime_series = pd.Series(dtype="float64")
    else:
        sleep_events["cycle_day"] = sleep_events["day"]
        sleep_events["bedtime_minutes"] = sleep_events["minute_of_day"]
        sleep_events.loc[sleep_events["bedtime_minutes"] < 12 * 60, "bedtime_minutes"] += 24 * 60
        sleep_events.loc[sleep_events["minute_of_day"] >= 12 * 60, "cycle_day"] = (
            sleep_events["cycle_day"] + pd.Timedelta(days=1)
        )
        bedtime_series = sleep_events.groupby("cycle_day")["bedtime_minutes"].min()
        bedtime_series = bedtime_series[(bedtime_series >= 20 * 60) & (bedtime_series <= 30 * 60)]

    commute_to = _apply_window(commute_to, window_start)
    commute_from = _apply_window(commute_from, window_start)
    workday = _apply_window(workday, window_start)
    out_of_home = _apply_window(out_of_home, window_start)
    bedtime_series = _apply_window(bedtime_series, window_start)

    left_home_hw = _apply_window(left_home_hw, window_start)
    arrive_work_hw = _apply_window(arrive_work_hw, window_start)
    arrive_work = _apply_window(arrive_work, window_start)
    left_work = _apply_window(left_work, window_start)
    arrive_home = _apply_window(arrive_home, window_start)
    left_work_wh = _apply_window(left_work_wh, window_start)
    arrive_home_wh = _apply_window(arrive_home_wh, window_start)

    commute_to_minutes = _series_to_minutes(commute_to)
    commute_from_minutes = _series_to_minutes(commute_from)
    workday_hours = _series_to_hours(workday)
    out_of_home_hours = _series_to_hours(out_of_home)

    commute_pair = pd.concat([commute_to_minutes.rename("to"), commute_from_minutes.rename("from")], axis=1).dropna()
    commute_total_minutes = commute_pair.sum(axis=1) if not commute_pair.empty else pd.Series(dtype="float64")

    work_start_clock = _series_to_clock_minutes(arrive_work)
    work_end_clock = _series_to_clock_minutes(left_work)
    left_work_for_commute = left_work_wh.combine_first(left_work)
    arrive_home_for_commute = arrive_home_wh.combine_first(arrive_home)

    commute_timeline_map = {
        "Left home": _series_to_clock_minutes(left_home_hw),
        "Arrived work": _series_to_clock_minutes(arrive_work_hw),
        "Left work": _series_to_clock_minutes(left_work_for_commute),
        "Arrived home": _series_to_clock_minutes(arrive_home_for_commute),
    }

    work_timeline_map = {
        "Arrived at work": _series_to_clock_minutes(arrive_work),
        "Left work": _series_to_clock_minutes(left_work),
    }

    commute_weekday = _weekday_dual_frame(commute_to_minutes, commute_from_minutes)
    work_weekday = _weekday_dual_frame(workday_hours, out_of_home_hours)
    sleep_weekday = _weekday_single_frame(bedtime_series)

    weeknight = bedtime_series[bedtime_series.index.weekday < 5]
    weekend = bedtime_series[bedtime_series.index.weekday >= 5]
    weekend_drift = None
    if not weeknight.empty and not weekend.empty:
        weekend_drift = _safe_mean(weekend) - _safe_mean(weeknight)

    tracked_days = events["day"].nunique()
    coverage_days = int((max_day - min_day).days) + 1
    contract_progress = _build_contract_tracking(workday_all_hours=workday_all_hours, latest_day=max_day)
    contract_history_rows = _build_contract_history_rows(workday_all_hours=workday_all_hours, latest_day=max_day)

    summary_cards = [
        {
            "label": "Events loaded",
            "value": "{0}".format(int(ingest_info["event_count"])),
            "meta": "{0} unparsable lines skipped".format(int(ingest_info["parse_failures"])),
        },
        {
            "label": "Tracked date span",
            "value": "{0} days".format(coverage_days),
            "meta": "{0} unique days with at least one event".format(int(tracked_days)),
        },
        {
            "label": "Commute day pairs",
            "value": "{0}".format(int(commute_total_minutes.count())),
            "meta": "days with both to-work and homebound commute",
        },
        {
            "label": "Sleep nights",
            "value": "{0}".format(int(bedtime_series.count())),
            "meta": "nights with a bedtime proxy",
        },
    ]

    coverage = "Coverage: {0} -> {1}".format(min_day.strftime("%Y-%m-%d"), max_day.strftime("%Y-%m-%d"))

    commute_insights: List[str] = []
    if not commute_to_minutes.empty:
        fastest_day = commute_to_minutes.idxmin()
        slowest_day = commute_to_minutes.idxmax()
        commute_insights.append(
            "Morning commute ranges from {0} to {1} ({2} -> {3}).".format(
                _format_minutes(commute_to_minutes.min()),
                _format_minutes(commute_to_minutes.max()),
                fastest_day.strftime("%Y-%m-%d"),
                slowest_day.strftime("%Y-%m-%d"),
            )
        )

    weekday_to_work = commute_weekday[["label", "mean_a"]].dropna()
    if not weekday_to_work.empty:
        quickest = weekday_to_work.loc[weekday_to_work["mean_a"].idxmin()]
        slowest = weekday_to_work.loc[weekday_to_work["mean_a"].idxmax()]
        commute_insights.append(
            "Quickest weekday is {0} ({1}); slowest is {2} ({3}).".format(
                quickest["label"],
                _format_minutes(quickest["mean_a"]),
                slowest["label"],
                _format_minutes(slowest["mean_a"]),
            )
        )

    if commute_total_minutes.empty:
        commute_insights.append("Not enough paired commute entries in this window.")

    work_insights: List[str] = []
    if not workday_hours.empty:
        longest_day = workday_hours.idxmax()
        shortest_day = workday_hours.idxmin()
        work_insights.append(
            "Workday length runs from {0} to {1} ({2} -> {3}).".format(
                _format_hours(workday_hours.min()),
                _format_hours(workday_hours.max()),
                shortest_day.strftime("%Y-%m-%d"),
                longest_day.strftime("%Y-%m-%d"),
            )
        )

    weekday_work = work_weekday[["label", "mean_a"]].dropna()
    if not weekday_work.empty:
        heaviest = weekday_work.loc[weekday_work["mean_a"].idxmax()]
        lightest = weekday_work.loc[weekday_work["mean_a"].idxmin()]
        work_insights.append(
            "Heaviest average workday is {0} ({1}); lightest is {2} ({3}).".format(
                heaviest["label"],
                _format_hours(heaviest["mean_a"]),
                lightest["label"],
                _format_hours(lightest["mean_a"]),
            )
        )

    if workday_hours.empty:
        work_insights.append("Not enough paired work-hour entries in this window.")

    if contract_progress["on_track"]:
        work_insights.append(
            "Current pace is on track: {0} logged vs {1} expected by {2}.".format(
                _format_decimal_hours(contract_progress["actual_hours"], 1),
                _format_decimal_hours(contract_progress["expected_to_date_hours"], 1),
                contract_progress["as_of"],
            )
        )
    else:
        work_insights.append(
            "Current pace is behind: {0} logged vs {1} expected by {2}.".format(
                _format_decimal_hours(contract_progress["actual_hours"], 1),
                _format_decimal_hours(contract_progress["expected_to_date_hours"], 1),
                contract_progress["as_of"],
            )
        )

    sleep_insights: List[str] = []
    if not bedtime_series.empty:
        earliest = bedtime_series.idxmin()
        latest = bedtime_series.idxmax()
        sleep_insights.append(
            "Bedtime proxy ranges from {0} to {1} ({2} -> {3}).".format(
                _format_clock(bedtime_series.min()),
                _format_clock(bedtime_series.max()),
                earliest.strftime("%Y-%m-%d"),
                latest.strftime("%Y-%m-%d"),
            )
        )

    if weekend_drift is not None:
        sleep_insights.append("Weekend bedtime drift vs weekdays: {0}.".format(_format_signed_minutes(weekend_drift)))

    if bedtime_series.empty:
        sleep_insights.append("Not enough sleep proxy entries in this window.")
    else:
        sleep_insights.append("Bedtime is inferred from first phone charge event each night.")

    commute_before_45 = _percent_before_threshold(commute_to_minutes, 45.0)
    raw_data = _build_raw_view_from_events(
        events=events,
        source="all",
        day=None,
        limit=120,
        window=normalized_window,
        window_start=window_start,
    )

    return {
        "window": normalized_window,
        "window_options": WINDOW_OPTIONS,
        "summary_cards": summary_cards,
        "coverage": coverage,
        "timeline_rows": _build_timeline_rows(_apply_window(events.set_index("day"), window_start).reset_index()),
        "raw": raw_data,
        "commute": {
            "metrics": [
                {
                    "label": "Average to work",
                    "value": _format_minutes(_safe_mean(commute_to_minutes)),
                    "meta": "{0} tracked mornings".format(int(commute_to_minutes.count())),
                },
                {
                    "label": "Average homebound",
                    "value": _format_minutes(_safe_mean(commute_from_minutes)),
                    "meta": "{0} tracked evenings".format(int(commute_from_minutes.count())),
                },
                {
                    "label": "Median total commute",
                    "value": _format_hours((_safe_median(commute_total_minutes) or 0.0) / 60.0)
                    if not commute_total_minutes.empty
                    else "-",
                    "meta": "to work + homebound on same day",
                },
                {
                    "label": "Morning consistency",
                    "value": _format_minutes(_safe_std(commute_to_minutes)),
                    "meta": "standard deviation, lower is steadier",
                },
                {
                    "label": "Best total commute",
                    "value": _format_hours((_safe_min(commute_total_minutes) or 0.0) / 60.0)
                    if not commute_total_minutes.empty
                    else "-",
                    "meta": "shortest full commute day",
                },
                {
                    "label": "<=45 min mornings",
                    "value": _format_percent(commute_before_45),
                    "meta": "share of mornings at or below 45 min",
                },
            ],
            "insights": commute_insights,
            "plot_main": _build_commute_duration_chart(commute_to_minutes, commute_from_minutes),
            "plot_weekday": _build_weekday_dual_bar(
                commute_weekday,
                title="Commute by Weekday",
                subtitle="Average duration sorted Monday to Sunday",
                y_title="Minutes",
                label_a="To work",
                label_b="Homebound",
            ),
            "plot_timeline": _build_clock_timeline_chart(
                commute_timeline_map,
                title="Commute Timeline",
                subtitle="Clock-time pattern across the selected window",
                y_min=6 * 60,
                y_max=19 * 60,
            ),
            "rows": _build_commute_rows(commute_to_minutes, commute_from_minutes),
            "weekday_rows": _build_commute_weekday_rows(commute_weekday),
        },
        "work": {
            "metrics": [
                {
                    "label": "Average workday",
                    "value": _format_hours(_safe_mean(workday_hours)),
                    "meta": "{0} tracked days".format(int(workday_hours.count())),
                },
                {
                    "label": "Average out of home",
                    "value": _format_hours(_safe_mean(out_of_home_hours)),
                    "meta": "{0} tracked days".format(int(out_of_home_hours.count())),
                },
                {
                    "label": "Average start time",
                    "value": _format_clock(_safe_mean(work_start_clock)),
                    "meta": "first arrive-at-work event",
                },
                {
                    "label": "Average finish time",
                    "value": _format_clock(_safe_mean(work_end_clock)),
                    "meta": "last leave-work event",
                },
                {
                    "label": "Longest workday",
                    "value": _format_hours(_safe_max(workday_hours)),
                    "meta": "single-day peak",
                },
                {
                    "label": "Shortest workday",
                    "value": _format_hours(_safe_min(workday_hours)),
                    "meta": "single-day low",
                },
            ],
            "insights": work_insights,
            "plot_main": _build_work_hours_chart(workday_hours, out_of_home_hours),
            "plot_weekday": _build_weekday_dual_bar(
                work_weekday,
                title="Workload by Weekday",
                subtitle="Average hours sorted Monday to Sunday",
                y_title="Hours",
                label_a="At work",
                label_b="Out of home",
            ),
            "plot_timeline": _build_clock_timeline_chart(
                work_timeline_map,
                title="Workday Timeline",
                subtitle="Arrival and departure clock-time pattern",
                y_min=7 * 60,
                y_max=18 * 60,
            ),
            "rows": _build_work_rows(workday_hours, out_of_home_hours),
            "weekday_rows": _build_work_weekday_rows(work_weekday),
            "contract_progress": contract_progress,
            "contract_history_rows": contract_history_rows,
        },
        "sleep": {
            "metrics": [
                {
                    "label": "Typical bedtime",
                    "value": _format_clock(_safe_mean(bedtime_series)),
                    "meta": "{0} nights tracked".format(int(bedtime_series.count())),
                },
                {
                    "label": "Median bedtime",
                    "value": _format_clock(_safe_median(bedtime_series)),
                    "meta": "midpoint night in this window",
                },
                {
                    "label": "Bedtime consistency",
                    "value": _format_minutes(_safe_std(bedtime_series)),
                    "meta": "standard deviation in minutes",
                },
                {
                    "label": "Weeknight average",
                    "value": _format_clock(_safe_mean(weeknight)),
                    "meta": "Monday to Friday nights",
                },
                {
                    "label": "Weekend average",
                    "value": _format_clock(_safe_mean(weekend)),
                    "meta": "Saturday and Sunday nights",
                },
                {
                    "label": "Weekend drift",
                    "value": _format_signed_minutes(weekend_drift),
                    "meta": "difference from weeknights",
                },
            ],
            "insights": sleep_insights,
            "plot_main": _build_sleep_trend_chart(bedtime_series),
            "plot_weekday": _build_weekday_single_bar(
                sleep_weekday,
                title="Bedtime by Weekday",
                subtitle="Average bedtime sorted Monday to Sunday",
                y_title="Clock time",
                clock_axis=True,
            ),
            "plot_distribution": _build_bedtime_distribution_chart(bedtime_series),
            "rows": _build_sleep_rows(bedtime_series),
            "weekday_rows": _build_sleep_weekday_rows(sleep_weekday),
        },
    }
