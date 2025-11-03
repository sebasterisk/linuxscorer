from vulnclasses import *

from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Label, Header, ProgressBar, ListView, ListItem, Footer
from textual.message import *
from textual.binding import Binding

import datetime

class Module(App):
    TITLE = "Linux Returner Diagnostic Image"
    CSS_PATH = "./css.tcss"
    
    VULNS = [
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^ANSWER:\s*192.168.133.1\s*$", in_path = Path("/home/sebastian/Desktop/Forensics Question 01")), points = 10, desc = "Correct response to Forensics 1"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^ANSWER:\s*forensics2{truthbehindthescarf}\s*$", in_path = Path("/home/sebastian/Desktop/Forensics Question 02")), points = 10, desc = "Correct response to Forensics 1"),

        # Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^ANSWER:\s*af7662b1c79e68aa873271ee5c9414ab\s*$", in_path = Path("/home/sebastian/Desktop/Forensics Question 02")), points = 10, desc = "Correct response to Forensics 2"),

        Vuln(
            Answer(CheckType.REGEX_NO_MATCH, checking_for = r"^adm.+kristoffer.+", in_path = Path("/etc/group")),
            Answer(CheckType.REGEX_NO_MATCH, checking_for = r"^sudo.+kristoffer.+", in_path = Path("/etc/group")),
            points = 5, desc = "User kristoffer is not an administrator"
        ),

        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for = "stadler", in_path = Path("/etc/group")), points = 5, desc = "Remove unauthorized user stadler"),
        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for = "maxwell", in_path = Path("/etc/group")), points = 5, desc = "Remove unauthorized user maxwell"),

        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^ENABLED=yes", in_path = Path("/etc/ufw/ufw.conf")), points = 5, desc = "UFW is enabled"),

        # Vuln(Answer(CheckType.SERVICE_DOWN, checking_for="apache2"), points = 5, desc = "Apache2 service removed or disabled"),
        # Vuln(Answer(CheckType.PATH_GONE, in_path=Path("/usr/games/freeciv-server")), points = 5, desc = "Unwanted software freeciv-server removed"),
        # Vuln(Answer(CheckType.PATH_GONE, in_path=Path("/usr/bin/wireshark")), points = 5, desc = "Unwanted software wireshark removed"),
        # Vuln(Answer(CheckType.PATH_GONE, in_path=Path("/home/hayden/Music/Vylet Pony - Huntress.mp3")), points = 5, desc = "Removed prohibited media files"),

        # Vuln(Answer(CheckType.STRING_FOUND_CMD_STDOUT, checking_for="TriggeredBy", command_to_run=["systemctl", "status", "mintupdate-automation-upgrade"]), points = 6, desc = "Updates are applied automatically"),
        # Vuln(Answer(CheckType.STRING_NOT_FOUND_CMD_STDOUT, checking_for="7.3.7.2", command_to_run=["libreoffice", "--version"]), points = 6, desc = "LibreOffice is updated"),
        # Vuln(Answer(CheckType.STRING_NOT_FOUND_CMD_STDOUT, checking_for="121.0", command_to_run=["firefox", "-v"]), points = 6, desc = "Firefox is updated"),

        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^PermitRootLogin no", in_path = Path("/etc/ssh/sshd_config")), points = 5, desc = "SSH root login disabled"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^X11Forwarding no", in_path = Path("/etc/ssh/sshd_config")), points = 5, desc = "SSH X11 forwarding disabled"),

        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"valid users = @adm\s*$", in_path = Path("/etc/samba/smb.conf")), points = 5, desc = "Removed unauthorized user from shared folder"),
        Vuln(Answer(CheckType.REGEX_NO_MATCH, checking_for = r"^\s*guest ok = yes", in_path = Path("/etc/samba/smb.conf")), points = 5, desc = "Samba disallows guest user"),
        Vuln(Answer(CheckType.REGEX_NO_MATCH, checking_for = r"guest account = sebastian", in_path = Path("/etc/samba/smb.conf")), points = 5, desc = "Samba does not use sebastian as guest user"),

        Vuln(Answer(CheckType.REGEX_NO_MATCH, checking_for = r"Require ip 192.168.133.1", in_path = Path("/etc/apache2/apache2.conf")), points = 5, desc = "The IP address no longer has access to unauthorized resources"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"ErrorDocument 404 /not_found.html", in_path = Path("/etc/apache2/sites-available/000-default.conf")), points = 5, desc = "The 404 error document is configured"),
        Vuln(Answer(CheckType.PATH_GONE, in_path = Path("/etc/apache2/sites-enabled/010-other.conf")), points = 5, desc = "Unauthorized website configuration disabled or removed"),
        Vuln(
            Answer(CheckType.STRING_NOT_FOUND, checking_for="james", in_path=Path("/etc/apache2/envvars")),
            Answer(CheckType.REGEX_MATCHES, checking_for=r"^export APACHE_RUN_USER=www-data", in_path=Path("/etc/apache2/envvars")),
            Answer(CheckType.REGEX_MATCHES, checking_for=r"^export APACHE_RUN_GROUP=www-data", in_path=Path("/etc/apache2/envvars")),
            points=5, desc="Apache runs as user www-data instead of user james"
        ),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^ServerTokens Prod", in_path = Path("/etc/apache2/conf-enabled/security.conf")), points = 5, desc = "Apache server tokens set to least"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^ServerSignature Off", in_path = Path("/etc/apache2/conf-enabled/security.conf")), points = 5, desc = "Apache server signature disabled"),

        Vuln(Answer(CheckType.STRING_FOUND_CMD_STDOUT, checking_for="refresh-schedule-enabled=true", command_to_run=["dconf", "dump", "/"]), points = 5, desc = "System refreshes list of updates automatically"),

        Vuln(Answer(CheckType.STRING_FOUND, checking_for = "0", in_path = Path("/proc/sys/net/ipv4/ip_forward")), points = 5, desc = "IP forwarding disabled"),
        Vuln(Answer(CheckType.STRING_FOUND, checking_for = "1", in_path = Path("/proc/sys/net/ipv4/conf/all/log_martians")), points = 5, desc = "Logs IPv4 martian packets"),

        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for = "wall -n", in_path = Path("/etc/crontab")), points = 5, desc = "Malicious crontab removed"),

        Vuln(Answer(CheckType.PATH_GONE, in_path=Path("/usr/sbin/4g8")), points = 5, desc = "Unwanted software 4g8 removed"),
        Vuln(Answer(CheckType.PATH_GONE, in_path=Path("/usr/bin/netcat")), points = 5, desc = "Unwanted software netcat removed"),
        Vuln(Answer(CheckType.PATH_GONE, in_path=Path("/usr/bin/php")), points = 5, desc = "Unwanted software PHP removed"),
    ]

    VULNLIST = VulnList(VULNS)

    BINDINGS = [
        Binding("f5", "update_score", "Refresh Now", tooltip = "Updates your score!"),
        Binding("q", "quit", "Exit", tooltip = "Leave the score report.")
    ]

    def compose(self) -> ComposeResult:
        yield Header(icon="")
        yield Container(
            ProgressBar(len(self.VULNS), show_eta=False, id="prog"),
            Label("", id="nvulns"),
            Label("", id="npoints"),
            id="upperinfo"
        )

        yield ListView(id="list")
        yield Label("", id="timeupdate")
        yield Footer(show_command_palette=False)
    
    def action_update_score(self) -> None:
        completed = self.VULNLIST.get_completed_vulns()
        points = self.VULNLIST.get_completed_vuln_score()
        total = self.VULNLIST.get_total_points()

        self.query_one("#nvulns").update(f"{len(completed)} out of {len(self.VULNS)} issues addressed")
        self.query_one("#npoints").update(f"{points} out of {total} points scored")
        self.query_one("#timeupdate").update(f"last update: {datetime.datetime.now().ctime()}")
        self.query_one("#prog").update(total = total, progress = points)

        self.query_one("#list").clear()
        for i in completed:
            self.query_one("#list").append(
                ListItem(
                    Label(f"{i.points} pts: {i.desc}"),
                )
            )

    def on_ready(self) -> None:
        self.action_update_score()
        self.set_interval(30, self.action_update_score, name = "refresher")


if __name__ == "__main__":
    app = Module()
    app.run()