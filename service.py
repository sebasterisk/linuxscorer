from vulnclasses import *

from pathlib import Path

from textual.app import App
from textual.message import *

import datetime
import json

class Module(App):
    TITLE = "Linux Returner Diagnostic Image"
    CSS_PATH = "./css.tcss"
    
    VULNS = [
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^ANSWER:\s*7.3.7.2\s*$", in_path = Path("/home/sebastian/Desktop/Forensics Question 01")), points = 10, desc = "Correct response to Forensics 1"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^ANSWER:\s*af7662b1c79e68aa873271ee5c9414ab\s*$", in_path = Path("/home/sebastian/Desktop/Forensics Question 02")), points = 10, desc = "Correct response to Forensics 2"),

        Vuln(
            Answer(CheckType.REGEX_NO_MATCH, checking_for = r"^adm.+cadan.+", in_path = Path("/etc/group")),
            Answer(CheckType.REGEX_NO_MATCH, checking_for = r"^sudo.+cadan.+", in_path = Path("/etc/group")),
            points = 5, desc = "User cadan is not an administrator"
        ),
        Vuln(
            Answer(CheckType.REGEX_MATCHES, checking_for = r"^helpers.+alan.+", in_path = Path("/etc/group")),
            points = 5, desc = "Changed appropriate groups for user alan"
        ),
        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for = "drtan", in_path = Path("/etc/group")), points = 5, desc = "Remove unauthorized user drtan"),
        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for = "eliot", in_path = Path("/etc/group")), points = 5, desc = "Remove unauthorized user eliot"),
        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for = "jason:$y$j9T$e.oa1ldxccK2Sa2p/", in_path = Path("/etc/shadow")), points = 5, desc = "Change insecure password for jason"),

        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^PASS_MAX_DAYS\s+[0-9]{1,3}", in_path = Path("/etc/login.defs")), points = 5, desc = "Password maximum age is set"),

        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^ENABLED=yes", in_path = Path("/etc/ufw/ufw.conf")), points = 5, desc = "UFW is enabled"),

        Vuln(Answer(CheckType.SERVICE_DOWN, checking_for="apache2"), points = 5, desc = "Apache2 service removed or disabled"),
        Vuln(Answer(CheckType.PATH_GONE, in_path=Path("/usr/games/freeciv-server")), points = 5, desc = "Unwanted software freeciv-server removed"),
        Vuln(Answer(CheckType.PATH_GONE, in_path=Path("/usr/bin/wireshark")), points = 5, desc = "Unwanted software wireshark removed"),
        Vuln(Answer(CheckType.PATH_GONE, in_path=Path("/home/hayden/Music/Vylet Pony - Huntress.mp3")), points = 5, desc = "Removed prohibited media files"),

        Vuln(Answer(CheckType.STRING_FOUND_CMD_STDOUT, checking_for="TriggeredBy", command_to_run=["systemctl", "status", "mintupdate-automation-upgrade"]), points = 6, desc = "Updates are applied automatically"),
        Vuln(Answer(CheckType.STRING_NOT_FOUND_CMD_STDOUT, checking_for="7.3.7.2", command_to_run=["libreoffice", "--version"]), points = 6, desc = "LibreOffice is updated"),
        Vuln(Answer(CheckType.STRING_NOT_FOUND_CMD_STDOUT, checking_for="121.0", command_to_run=["firefox", "-v"]), points = 6, desc = "Firefox is updated"),

        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^PermitRootLogin no", in_path = Path("/etc/ssh/sshd_config")), points = 6, desc = "SSH root login disabled"),
    ]

    VULNLIST = VulnList(VULNS)
    
    def action_update_score(self) -> None:
        completed = self.VULNLIST.get_completed_vulns()
        points = self.VULNLIST.get_completed_vuln_score()
        total = self.VULNLIST.get_total_points()
        
        full = {
            "pointsAttained": points,
            "pointsTotal": total,
            
            "vulnsCompleted": len(completed),
            "vulnsTotal": len(self.VULNS),

            "completedVulnDescription": [ x for x in completed ]   
        }
        
        with open("score.json", "w") as f:
            json.dump(full, f, indent=4)

    def on_ready(self) -> None:
        self.action_update_score()
        self.set_interval(30, self.action_update_score, name = "refresher")


if __name__ == "__main__":
    app = Module()
    app.run()