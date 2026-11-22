
"""Deterministic offline rules. A finding is a clue, never proof of compromise."""

import re

from sentinel.core.models import Event, Finding


RULES = [
    # Authentication
    (
        "ssh_failed_password",
        ("failed password", "authentication failure", "failed publickey"),
        "Failed SSH sign-in",
        "Authentication",
        "medium",
        "The system recorded an unsuccessful authentication attempt.",
        "A single failure can be a typo. Repeated failures may deserve review.",
        "Review nearby SSH events and confirm that the account and access policy are expected.",
    ),
    (
        "ssh_invalid_user",
        ("invalid user", "user unknown"),
        "SSH attempt for an unknown account",
        "Authentication",
        "medium",
        "A login was attempted using an account name the system does not recognize.",
        "Automated scanners often try common usernames; this alone does not prove access was gained.",
        "Check the source address and nearby SSH events. Restrict SSH access where practical.",
    ),
    (
        "sudo_auth",
        ("sudo:", "pam_unix(sudo"),
        "Privilege authentication event",
        "Privileges",
        "medium",
        "A privileged command or authentication check generated this event.",
        "Unexpected privilege prompts or failures can indicate misuse, but normal administration can produce them too.",
        "Confirm the user and time are expected. Review the complete original log entry.",
    ),

    # Security policies
    (
        "selinux_denial",
        ("avc: denied", "selinux is preventing", "type=avc"),
        "SELinux blocked an operation",
        "Security policy",
        "medium",
        "SELinux policy prevented a process from performing an operation.",
        "This may be expected protection or an application configuration issue; it is not automatically an attack.",
        "Inspect the process, target path, and SELinux context. Do not disable SELinux to silence the message.",
    ),
    (
        "apparmor_denial",
        ('apparmor="denied"', "apparmor denied"),
        "AppArmor blocked an operation",
        "Security policy",
        "medium",
        "An AppArmor profile denied an application action.",
        "The profile may be containing an application correctly or may need careful review.",
        "Identify the application and denied operation. Review the profile before changing policy.",
    ),

    # Desktop diagnostics
    (
        "desktop_widget_diagnostic",
        (
            "_checkfullscreen:",
            "animationspaused=",
            "hasfullscreen=",
            "windowcount=",
        ),
        "Desktop diagnostic message",
        "Desktop",
        "info",
        "A desktop component reported routine window or animation state.",
        "This is normally diagnostic information and does not indicate a security incident.",
        "No action is normally required. Review the original message if the desktop is behaving unexpectedly.",
    ),

    # Desktop environments
    (
        "gnome_desktop",
        (
            "gnome-shell",
            "gnome-session",
            "gnome-settings-daemon",
            "gnome-control-center",
            "gnome-software",
            "gnome-screensaver",
            "gnome-desktop",
            "nautilus",
            "mutter",
        ),
        "GNOME desktop event",
        "Desktop",
        "low",
        "A GNOME desktop component generated this event.",
        "Desktop components produce routine session messages and may also report graphical or configuration problems.",
        "No action is normally required unless you notice desktop, session, or graphical issues.",
    ),
    (
        "kde_plasma_desktop",
        (
            "plasmashell",
            "plasma-desktop",
            "plasma_session",
            "plasma-workspace",
            "kded",
            "kglobalaccel",
            "ksmserver",
            "kwin",
            "systemsettings",
            "dolphin",
            "kactivitymanagerd",
        ),
        "KDE Plasma desktop event",
        "Desktop",
        "low",
        "A KDE Plasma component generated this event.",
        "Plasma components generate routine session, window-management, and desktop-service messages.",
        "No action is normally required unless Plasma features or the graphical session are malfunctioning.",
    ),
    (
        "xfce_desktop",
        (
            "xfce4-session",
            "xfce4-panel",
            "xfce4-settings",
            "xfsettingsd",
            "xfdesktop",
            "xfwm4",
            "thunar",
            "xfce-polkit",
        ),
        "Xfce desktop event",
        "Desktop",
        "low",
        "An Xfce desktop component generated this event.",
        "These messages may describe normal desktop activity or configuration and session problems.",
        "Check nearby messages if the panel, window manager, or desktop session is malfunctioning.",
    ),
    (
        "cinnamon_desktop",
        (
            "cinnamon",
            "cinnamon-session",
            "cinnamon-settings",
            "muffin",
            "nemo",
            "cinnamon-screensaver",
        ),
        "Cinnamon desktop event",
        "Desktop",
        "low",
        "A Cinnamon desktop component generated this event.",
        "Cinnamon components may report routine session activity or graphical issues.",
        "Inspect nearby messages if the desktop, panel, or window manager behaves unexpectedly.",
    ),
    (
        "mate_desktop",
        (
            "mate-session",
            "mate-panel",
            "mate-settings-daemon",
            "mate-screensaver",
            "marco",
            "caja",
        ),
        "MATE desktop event",
        "Desktop",
        "low",
        "A MATE desktop component generated this event.",
        "These messages are commonly related to session management, desktop settings, or window management.",
        "Check nearby messages if a MATE desktop component is not working correctly.",
    ),
    (
        "lxqt_desktop",
        (
            "lxqt-session",
            "lxqt-panel",
            "lxqt-config",
            "lxqt-globalkeys",
            "pcmanfm-qt",
            "qterminal",
        ),
        "LXQt desktop event",
        "Desktop",
        "low",
        "An LXQt desktop component generated this event.",
        "LXQt components produce routine session and desktop-service messages.",
        "Inspect nearby messages if the panel, session, or desktop configuration is malfunctioning.",
    ),
    (
        "lxde_desktop",
        (
            "lxsession",
            "lxpanel",
            "pcmanfm",
            "lxappearance",
            "lxpolkit",
        ),
        "LXDE desktop event",
        "Desktop",
        "low",
        "An LXDE desktop component generated this event.",
        "These messages are generally related to the desktop session and its components.",
        "Check nearby messages if the desktop session or panel is malfunctioning.",
    ),
    (
        "budgie_desktop",
        (
            "budgie-desktop",
            "budgie-panel",
            "budgie-wm",
            "budgie-daemon",
        ),
        "Budgie desktop event",
        "Desktop",
        "low",
        "A Budgie desktop component generated this event.",
        "Budgie components may report routine session activity or desktop problems.",
        "Inspect nearby messages if the panel or desktop session is not working correctly.",
    ),
    (
        "cosmic_desktop",
        (
            "cosmic-session",
            "cosmic-comp",
            "cosmic-panel",
            "cosmic-settings",
            "cosmic-greeter",
            "cosmic-files",
        ),
        "COSMIC desktop event",
        "Desktop",
        "low",
        "A COSMIC desktop component generated this event.",
        "COSMIC components may report routine session activity or graphical issues.",
        "Check nearby messages if the desktop session or its components are malfunctioning.",
    ),

    # Standalone window managers and Wayland compositors
    (
        "openbox_wm",
        ("openbox",),
        "Openbox window manager event",
        "Desktop",
        "low",
        "The Openbox window manager generated this event.",
        "This may be routine window-management activity or a configuration issue.",
        "Inspect nearby messages if windows are not behaving as expected.",
    ),
    (
        "i3_wm",
        ("i3", "i3-msg"),
        "i3 window manager event",
        "Desktop",
        "low",
        "The i3 window manager generated this event.",
        "Window manager messages may describe normal workspace activity or configuration problems.",
        "Check the i3 configuration and nearby messages if window management is malfunctioning.",
    ),
    (
        "sway_compositor",
        ("sway", "swaymsg"),
        "Sway compositor event",
        "Desktop",
        "low",
        "The Sway Wayland compositor generated this event.",
        "These messages may describe routine compositor activity or display configuration problems.",
        "Inspect nearby messages and the Sway configuration if graphical problems occur.",
    ),
    (
        "hyprland_compositor",
        ("hyprland", "hyprctl"),
        "Hyprland compositor event",
        "Desktop",
        "low",
        "The Hyprland Wayland compositor generated this event.",
        "These messages may describe routine compositor activity, configuration, or rendering problems.",
        "Check nearby messages and the Hyprland configuration if the compositor behaves unexpectedly.",
    ),
    (
        "bspwm_wm",
        ("bspwm", "bspc"),
        "bspwm window manager event",
        "Desktop",
        "low",
        "The bspwm window manager generated this event.",
        "This may be routine window-management activity or a configuration issue.",
        "Inspect the bspwm configuration if windows or desktops behave unexpectedly.",
    ),
    (
        "awesome_wm",
        ("awesome", "awesomewm"),
        "Awesome window manager event",
        "Desktop",
        "low",
        "The Awesome window manager generated this event.",
        "These messages may describe routine window management or Lua configuration problems.",
        "Inspect nearby messages and the Awesome configuration if the window manager malfunctions.",
    ),
    (
        "dwm_wm",
        ("dwm",),
        "dwm window manager event",
        "Desktop",
        "low",
        "The dwm window manager generated this event.",
        "This may be routine window-management activity or a configuration issue.",
        "Check nearby messages if the window manager behaves unexpectedly.",
    ),
    (
        "river_compositor",
        ("river", "riverctl"),
        "River compositor event",
        "Desktop",
        "low",
        "The River Wayland compositor generated this event.",
        "These messages may describe routine compositor activity or configuration problems.",
        "Inspect nearby messages and the River configuration if graphical issues occur.",
    ),
    (
        "wayfire_compositor",
        ("wayfire",),
        "Wayfire compositor event",
        "Desktop",
        "low",
        "The Wayfire compositor generated this event.",
        "This may be routine compositor activity or a graphics configuration issue.",
        "Check nearby messages if the compositor or its plugins behave unexpectedly.",
    ),
    (
        "labwc_compositor",
        ("labwc",),
        "Labwc compositor event",
        "Desktop",
        "low",
        "The Labwc Wayland compositor generated this event.",
        "These messages may describe routine compositor activity or configuration problems.",
        "Inspect nearby messages if windows or the graphical session malfunction.",
    ),

    # Display managers
    (
        "display_manager",
        (
            "gdm",
            "gdm-session",
            "sddm",
            "lightdm",
            "lxdm",
            "greetd",
        ),
        "Display manager event",
        "Desktop",
        "low",
        "A graphical login manager generated this event.",
        "These messages may describe normal login activity or graphical session startup problems.",
        "Check nearby messages if login, authentication, or session startup fails.",
    ),

    # Display and graphics systems
    (
        "xorg_graphics",
        ("xorg", "x server", "xwayland", "x11 connection"),
        "X11 graphics event",
        "Graphics",
        "low",
        "An X11 or Xwayland component generated this event.",
        "These messages may describe normal display activity or graphical application problems.",
        "Check nearby messages if graphical applications fail to connect or render correctly.",
    ),

    (
        "wayland_graphics",
        ("wayland", "wayland display", "wl_display"),
        "Wayland graphics event",
        "Graphics",
        "low",
        "A Wayland-related component generated this event.",
        "These messages may describe normal display communication or compositor problems.",
        "Inspect nearby messages if graphical applications or the display session malfunction.",
    ),
    # Desktop services
    (
        "desktop_portal",
        (
            "xdg-desktop-portal",
            "org.freedesktop.portal",
            "desktop portal",
        ),
        "Desktop portal event",
        "Desktop",
        "low",
        "A desktop portal service generated this event.",
        "Portal services handle desktop integration such as file access, screenshots, and application permissions.",
        "Inspect nearby messages if sandboxed applications cannot access desktop features.",
    ),
    (
        "desktop_notifications",
        (
            "org.freedesktop.notifications",
            "notification daemon",
            "notification-daemon",
            "dunst",
            "mako",
            "swaync",
        ),
        "Desktop notification event",
        "Desktop",
        "low",
        "A desktop notification component generated this event.",
        "Notification services commonly generate routine messages during desktop activity.",
        "No action is normally required unless notifications stop working.",
    ),
    (
        "desktop_dbus",
        (
            "dbus-daemon",
            "dbus-broker",
            "org.freedesktop.dbus",
        ),
        "Desktop message bus event",
        "Desktop",
        "low",
        "The D-Bus message bus generated this event.",
        "D-Bus is used by desktop applications and system services to communicate.",
        "Inspect nearby messages if desktop applications cannot communicate with system services.",
    ),

    # System and hardware
    (
        "segfault",
        ("segfault", "general protection fault"),
        "Application or process crashed",
        "Kernel / Process",
        "medium",
        "The kernel recorded an invalid memory access or process fault.",
        "Crashes can cause data loss or service interruption; they do not establish malicious activity.",
        "Identify the affected program, check for updates, and inspect related crash reports.",
    ),
    (
        "service_failed",
        ("failed to start", "failed with result", "main process exited", "dependency failed"),
        "A service failed",
        "Services",
        "medium",
        "A service did not start or exited unexpectedly.",
        "Features depending on the service may be unavailable.",
        "Check the service name and nearby logs. Investigate its configuration if the failure repeats.",
    ),
    (
        "disk_space",
        ("no space left on device", "filesystem full", "read-only file system"),
        "Storage problem detected",
        "Storage",
        "high",
        "A process could not write data or encountered a storage state problem.",
        "Applications may fail, logs may stop recording, and data integrity can be affected.",
        "Check filesystem usage and mount status. Do not delete unfamiliar files to make space.",
    ),
    (
        "hardware_io",
        ("i/o error", "hardware error", "mce:", "machine check"),
        "Kernel reported a hardware or I/O problem",
        "Kernel / Hardware",
        "high",
        "The kernel logged a hardware, memory, or storage I/O error.",
        "Repeated errors can indicate an unreliable device or driver issue.",
        "Back up important data and inspect related kernel messages and device health.",
    ),
    (
        "network_link",
        ("link is down", "carrier lost", "network is unreachable"),
        "Network connectivity changed",
        "Network",
        "low",
        "A network interface or route became unavailable.",
        "This may be normal when connecting, disconnecting, or switching networks.",
        "If connectivity is unexpectedly lost, check the interface and network-service logs.",
    ),
    (
        "oom",
        ("out of memory", "oom-kill", "killed process"),
        "System ran low on memory",
        "System health",
        "high",
        "The kernel reported memory pressure and may have terminated a process.",
        "Applications can become unresponsive or be stopped unexpectedly.",
        "Check memory usage and the process named in the original event; investigate possible memory leaks.",
    ),
]



def _normalize_component(value: str) -> str:
    """Normalize an executable, identifier, or systemd unit name."""
    value = (value or "").casefold().strip()
    value = value.rsplit("/", 1)[-1]
    value = re.sub(r"\[\d+\]$", "", value)

    for suffix in (
        ".service",
        ".scope",
        ".socket",
        ".target",
        ".desktop",
        ".exe",
    ):
        if value.endswith(suffix):
            value = value[:-len(suffix)]
            break

    return value


def _component_matches(component: str, term: str) -> bool:
    """Match a component name without matching arbitrary substrings."""
    component = _normalize_component(component)
    term = term.casefold().strip()

    if not component or not term:
        return False

    if component == term:
        return True

    if component.startswith(term):
        next_char = component[len(term)]
        return next_char in "-_.@+"

    return False


def _contains_term(text: str, term: str) -> bool:
    """Match a phrase or token with alphanumeric boundaries."""
    text = (text or "").casefold()
    term = term.casefold().strip()

    if not text or not term:
        return False

    pattern = re.escape(term)

    if term[0].isalnum():
        pattern = r"(?<![a-z0-9])" + pattern

    if term[-1].isalnum():
        pattern += r"(?![a-z0-9])"

    return re.search(pattern, text) is not None


def _message_component(message: str) -> str:
    """Extract a conventional process prefix such as gnome-shell[123]:."""
    match = re.match(
        r"^\s*([a-zA-Z0-9_.@+-]+)(?:\[\d+\])?\s*:",
        message or "",
    )
    return match.group(1) if match else ""


def _rule_matches(
    event: Event,
    rule_id: str,
    terms: tuple,
    category: str,
) -> bool:
    message = event.message or ""

    # Widget diagnostics are identified by their explicit diagnostic fields.
    if rule_id == "desktop_widget_diagnostic":
        return any(term.casefold() in message.casefold() for term in terms)

    # Desktop and graphics rules must identify an actual component.
    # Merely mentioning a desktop name in prose is not sufficient.
    if category in ("Desktop", "Graphics"):
        components = (
            event.identifier or "",
            event.unit or "",
            _message_component(message),
        )

        return any(
            _component_matches(component, term)
            for component in components
            for term in terms
        )

    # Security and system rules inspect the actual event content.
    searchable = " ".join(
        (
            message,
            event.identifier or "",
            event.unit or "",
        )
    )

    return any(_contains_term(searchable, term) for term in terms)


def _desktop_severity(event: Event, original: str) -> str:
    """Never downgrade a desktop event with an elevated journal priority."""
    if event.priority <= 2:
        return "critical"
    if event.priority == 3:
        return "high"
    if event.priority == 4:
        return "medium"
    if event.priority == 5:
        return "low"

    return original


def explain(event: Event) -> Finding:
    """Explain an event using deterministic English-only rules."""

    # System, authentication, security, kernel and hardware rules first.
    # Desktop rules must never hide a more important system finding.
    ordered_rules = (
        [rule for rule in RULES if rule[3] not in ("Desktop", "Graphics")]
        + [rule for rule in RULES if rule[3] in ("Desktop", "Graphics")]
    )

    for (
        rule_id,
        terms,
        title,
        category,
        severity,
        summary,
        why,
        action,
    ) in ordered_rules:
        if not _rule_matches(event, rule_id, terms, category):
            continue

        if category in ("Desktop", "Graphics"):
            severity = _desktop_severity(event, severity)

        return Finding(
            event=event,
            title=title,
            category=category,
            severity=severity,
            summary=summary,
            why_it_matters=why,
            recommendation=action,
            confidence="medium",
            rule_id=rule_id,
        )

    if event.priority <= 2:
        severity, title = "critical", "Critical system event"
    elif event.priority == 3:
        severity, title = "high", "System error"
    elif event.priority == 4:
        severity, title = "medium", "System warning"
    elif event.priority == 5:
        severity, title = "low", "System notice"
    else:
        severity, title = "info", "System information"

    return Finding(
        event=event,
        title=title,
        category="General",
        severity=severity,
        summary="Sentinel has no specific explanation rule for this message.",
        why_it_matters="Journal priority is a logging hint, not proof of a security incident.",
        recommendation="Read the original message and check nearby events if something appears unexpected.",
        confidence="low",
        rule_id="generic",
    )
