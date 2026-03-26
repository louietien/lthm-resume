PROJECTS_DATA = {
    "page_title": "Projects | Louie Hegeler-Meile",
    "theme": {
        "dark_label": "Dark Mode",
        "light_label": "Light Mode",
    },
    "filters": ["All", "Node.js", "React", "Python", "PowerShell"],
    "projects": [
        {
            "name": "215kbase",
            "category": "Node.js",
            "description": "Markdown-first internal knowledge base with a web editor, section/category browsing, and image upload.",
            "stack": ["Node.js", "Express", "Markdown"],
            "version": "1.11.0",
        },
        {
            "name": "itkbase",
            "category": "Node.js",
            "description": "IT-focused knowledge base variant rebuilt around a new design direction with Entra SSO.",
            "stack": ["Node.js", "Express", "Entra SSO"],
            "version": "1.11.0",
        },
        {
            "name": "nodekbase",
            "category": "Node.js",
            "description": "Earlier knowledge base iteration with added Entra SSO, rate limiting, and proxy-aware cookie controls.",
            "stack": ["Node.js", "Express", "Entra SSO"],
            "version": "1.9.3",
        },
        {
            "name": "status-page",
            "category": "Node.js",
            "description": "Lightweight IT ops status page with live SSE updates, incident lifecycle management, soft-delete, and audit log.",
            "stack": ["Node.js", "SSE", "JSON"],
            "version": None,
        },
        {
            "name": "erderfrokost",
            "category": "Node.js",
            "description": "Danish office lunch-bell tracker — who rang first today, race leaderboard, cooldown enforcement, and historical log.",
            "stack": ["Node.js", "Express", "JSON"],
            "version": None,
        },
        {
            "name": "ferie-monday",
            "category": "Node.js",
            "description": "Holiday overview pulling vacation data from Monday.com with daily refresh, Azure AD SSO, and admin CRUD.",
            "stack": ["Node.js", "Monday.com", "Azure AD"],
            "version": None,
        },
        {
            "name": "blog-builder",
            "category": "Node.js",
            "description": "Client-side HTML builder for creating consistent, structured WordPress blog posts.",
            "stack": ["Node.js", "Express", "HTML"],
            "version": None,
        },
        {
            "name": "215parking",
            "category": "Node.js",
            "description": "Automates Avantpark license plate registration via Playwright with a minimal web UI and Danish plate validation.",
            "stack": ["Node.js", "Playwright", "Express"],
            "version": "1.2.3",
        },
        {
            "name": "admin-index",
            "category": "Node.js",
            "description": "Minimal static portal index hosted on Azure App Service, serving as an internal landing page.",
            "stack": ["Node.js", "Azure"],
            "version": None,
        },
        {
            "name": "orgdia",
            "category": "React",
            "description": "Local org chart editor built with React Flow, with Microsoft 365 manager sync via MS Graph API.",
            "stack": ["React", "React Flow", "MS Graph"],
            "version": None,
        },
        {
            "name": "eotf-vendor-creation-form",
            "category": "React",
            "description": "Internal vendor creation form for structured procurement workflows.",
            "stack": ["React", "Vite"],
            "version": None,
        },
        {
            "name": "lthm-resume",
            "category": "Python",
            "description": "This site — personal portfolio with a private stats dashboard built with Flask, Plotly, and HTMX.",
            "stack": ["Python", "Flask", "Plotly"],
            "version": None,
        },
        {
            "name": "ms-admin-tools",
            "category": "PowerShell",
            "description": "Browser-based admin console for Microsoft 365 — mailbox delegation, on/offboarding, user creation and deletion.",
            "stack": ["PowerShell", "M365", "Exchange"],
            "version": None,
        },
        {
            "name": "on-offboarding",
            "category": "PowerShell",
            "description": "PowerShell GUI wrapper using a host + config model for flexible on/offboarding automation.",
            "stack": ["PowerShell", "GUI"],
            "version": None,
        },
        {
            "name": "Offboarding",
            "category": "PowerShell",
            "description": "Standalone PowerShell scripts for Microsoft 365 offboarding — auto-reply, license removal, and account cleanup.",
            "stack": ["PowerShell", "M365"],
            "version": None,
        },
        {
            "name": "ps-gui-win",
            "category": "PowerShell",
            "description": "Mail Delegate Controller — PowerShell-backed web GUI for Exchange Online delegation management.",
            "stack": ["PowerShell", "Exchange", "GUI"],
            "version": None,
        },
        {
            "name": "scripts",
            "category": "PowerShell",
            "description": "Collection of PowerShell scripts for identity management, group exports, and MS Graph operations.",
            "stack": ["PowerShell", "MS Graph", "Exchange"],
            "version": None,
        },
    ],
}

SITE_DATA = {
    "page_title": "Louie Hegeler-Meile | Portfolio",
    "theme": {
        "dark_label": "Dark Mode",
        "light_label": "Light Mode",
    },
    "quick_nav": [
        {"href": "#about", "label": "About"},
        {"href": "#experience", "label": "Experience"},
        {"href": "#projects", "label": "Projects"},
        {"href": "#skills", "label": "Skills"},
        {"href": "#contact", "label": "Contact"},
    ],
    "hero": {
        "eyebrow": "Tech, Music, and IT Ops",
        "nameplate": "Louie Hegeler-Meile",
        "intro": "I'm",
        "roles": [
            "senior IT Ops Specialist",
            "sysadmin",
            "M365 + Azure admin",
            "hands-on troubleshooter",
            "PC builder",
            "music nerd",
            "friendly-neighborhood IT-guy",
            "curious problem solver",
            "bit of a cinephile...",
        ],
        "subtitle": (
            "I make sure IT at 21-5 works the way it should. I handle device setup, "
            "Microsoft 365 and Azure admin, and jump on weird issues before they become "
            "big headaches."
        ),
        "actions": [
            {
                "href": "https://www.linkedin.com/in/louiehegelermeile",
                "label": "LinkedIn Profile",
                "ghost": False,
                "external": True,
            },
            {
                "label": "Contact Info",
                "ghost": True,
                "popup": True,
            },
        ],
        "contact_popup": {
            "email": "lt@lthm.dk",
            "phone": "+4521302242",
        },
        "location": "Copenhagen, Capital Region of Denmark, Denmark",
        "stats": [
            "Danish + English",
            "Driving License (B)",
            "IT Operations @ 21-5",
            "PC Builder",
        ],
        "wins": [
            {"value": "Day Job", "label": "keeping internal IT smooth at 21-5"},
            {"value": "Background", "label": "strong 2nd-line Apple troubleshooting"},
            {"value": "Off Hours", "label": "music, gaming, travel, and PC builds"},
        ],
    },
    "about": {
        "title": "About",
        "paragraphs": [
            (
                "Hey, I'm Louie. I'm an IT professional with a habit of fixing what's "
                "broken and building what doesn't exist yet."
            ),
            (
                "In my current role, I manage and extend internal platforms, automate "
                "repetitive workflows, and build tooling from scratch when off-the-shelf "
                "options don't cut it. I spot broken processes and fix them — whether "
                "that means a configuration change or writing something new."
            ),
            (
                "Before that, I did 2nd-line technical support for Apple, handling "
                "escalations from clients and service providers worldwide. That gave me "
                "the client-facing composure and structured thinking that purely technical "
                "roles don't always develop."
            ),
            (
                "Outside work, I build PCs, write code for fun, and used to volunteer "
                "in r/techsupport — helping strangers debug real problems remotely."
            ),
        ],
    },
    "experience": {
        "title": "Experience",
        "items": [
            {
                "logo": {"type": "image", "src": "logos/21-5.jpg", "alt": "21-5 logo"},
                "title": "Senior IT Operations Specialist",
                "meta": "21-5 | Apr 2025 - Present | Hørsholm, Denmark",
                "description": (
                    "Oversee day-to-day IT operations, IT logistics, platform reliability, "
                    "endpoint lifecycle management, and equipment procurement. I spot weak "
                    "or outdated workflows and drive continuous improvement with better, "
                    "more practical solutions."
                ),
            },
            {
                "logo": {"type": "image", "src": "logos/21-5.jpg", "alt": "21-5 logo"},
                "title": "IT Operations Specialist",
                "meta": "21-5 | Sep 2021 - Apr 2025",
                "description": (
                    "Managed Microsoft Exchange and Microsoft 365 administration, Azure "
                    "DevOps workflows, and operational service delivery across modern "
                    "workplace tooling."
                ),
            },
            {
                "logo": {
                    "type": "image",
                    "src": "logos/webhelp.jpg",
                    "alt": "Webhelp logo",
                },
                "title": "Senior Technical Advisor",
                "meta": "Webhelp | Aug 2020 - Aug 2021 | Copenhagen",
                "description": (
                    "Led second-line technical incident handling, managed high-priority "
                    "escalations, and coordinated complex repair workflows with "
                    "authorized service providers worldwide."
                ),
            },
            {
                "logo": {
                    "type": "image",
                    "src": "logos/webhelp.jpg",
                    "alt": "Webhelp logo",
                },
                "title": "Technical Advisor",
                "meta": "Webhelp | Jan 2020 - Jul 2020",
                "description": (
                    "Provided technical troubleshooting across Apple platforms, building "
                    "a strong foundation in diagnostics and structured escalation."
                ),
            },
            {
                "logo": {
                    "type": "image",
                    "src": "logos/vinstue-90.jpg",
                    "alt": "Vinstue 90 logo",
                },
                "title": "HR Business Partner",
                "meta": "Vinstue 90 | Aug 2015 - Present (multiple roles)",
                "description": (
                    "Managed payroll and tax reporting, coordinated shifts, and supported "
                    "onboarding and training."
                ),
            },
            {
                "logo": {"type": "badge", "text": "H"},
                "title": "Storage Helper",
                "meta": "HARTUNG Men's Wear | Sep 2014 - Aug 2018",
                "description": (
                    "Handled stock logistics, customer service, and in-store sales support."
                ),
            },
        ],
    },
    "projects_section": {
        "title": "Projects",
        "description": "Internal tools, automations, and web apps I've built on the side.",
        "cta_label": "View all projects",
        "cta_href": "/projects",
        "projects": [
            {
                "title": "Knowledge Base (215kbase / itkbase)",
                "description": "Markdown-first internal knowledge base with a web editor, section/category browsing, and image upload. Deployed in two variants.",
            },
            {
                "title": "ferie-monday",
                "description": "Holiday overview pulling vacation data from Monday.com with Azure AD SSO, daily refresh, and admin CRUD.",
            },
            {
                "title": "status-page",
                "description": "Lightweight IT ops status page with live SSE updates, incident lifecycle management, and audit log.",
            },
            {
                "title": "ms-admin-tools",
                "description": "Browser-based admin console for Microsoft 365 — mailbox delegation, user on/offboarding, and account lifecycle.",
            },
        ],
    },
    "skills": {
        "title": "Skills",
        "items": [
            "IT Operations",
            "Systems Administration",
            "Microsoft 365 Administration",
            "Microsoft Exchange",
            "Azure Administration",
            "Azure DevOps",
            "Troubleshooting (Hardware + Software)",
            "Automation & Scripting",
            "iOS",
            "macOS",
            "tvOS",
            "watchOS",
            "Microsoft Office",
            "Adobe Suite",
            "PC Building",
            "Danish (Native)",
            "English (Fluent)",
            "Driving License (B)",
            "Payroll & Tax Reporting",
            "Recruiting & Coaching",
        ],
        "education_title": "Education",
        "education": [
            {
                "school": "Rysensteen Gymnasium",
                "meta": "High School | 2017 - 2019",
                "description": "Music A, English A, Maths B.",
            },
            {
                "school": "Skolen ved Søerne",
                "meta": "Primary School | 2007 - 2017",
                "description": "",
            },
        ],
    },
    "snapshot": {
        "title": "More About Me",
        "items": [
            {
                "title": "What I Do",
                "description": (
                    "I keep internal IT stable and usable so people can do their work "
                    "without fighting their tools."
                ),
            },
            {
                "title": "How I Work",
                "description": (
                    "Curious, practical, and a bit perfectionist. I like digging into "
                    "details and fixing root causes, especially when a process is clunky "
                    "and can be done better."
                ),
            },
            {
                "title": "Outside Work",
                "description": (
                    "Music, gaming, travel, and PC building take up most of my free time."
                ),
            },
            {
                "title": "Community",
                "description": (
                    "I used to volunteer in r/techsupport and enjoyed helping people "
                    "solve technical issues from scratch."
                ),
            },
        ],
    },
    "contact": {
        "title": "Say Hi",
        "description": (
            "If you need someone practical who can keep IT running and is easy to work "
            "with, feel free to reach out."
        ),
        "actions": [
            {
                "href": "mailto:mail@louietien.com",
                "label": "Email Me",
                "ghost": False,
                "external": False,
            },
            {
                "href": "https://www.linkedin.com/in/louiehegelermeile",
                "label": "Message on LinkedIn",
                "ghost": True,
                "external": True,
            },
        ],
    },
}
