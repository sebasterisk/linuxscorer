from vulnclasses import *

from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Label, Header, ProgressBar, ListView, ListItem, Footer
from textual.message import *
from textual.binding import Binding

import datetime

class Module(App):
    TITLE = "Linux Beginner Lab 2 - Passwords & Sudoers"
    CSS_PATH = "./css.tcss"
    
    VULNS = [ 
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for= r"^password\s+requisite\s+pam_pwquality\.so", in_path=Path("/etc/pam.d/common-password")), points=5, desc="pwquality is used in PAM"),
        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for="nullok", in_path=Path("/etc/pam.d/common-password")), points=5, desc="null passwords do not validate"),

        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^\s*minlen\s*=\s*12", in_path = Path("/etc/security/pwquality.conf")), points = 5, desc = "Password must be at least 12 characters in length"),
        
        Vuln(
            Answer(CheckType.REGEX_MATCHES, checking_for = r"^\s*dcredit\s*=\s*-1", in_path = Path("/etc/security/pwquality.conf")), 
            Answer(CheckType.REGEX_MATCHES, checking_for = r"^\s*ucredit\s*=\s*-1", in_path = Path("/etc/security/pwquality.conf")), 
            Answer(CheckType.REGEX_MATCHES, checking_for = r"^\s*lcredit\s*=\s*-1", in_path = Path("/etc/security/pwquality.conf")), 
            Answer(CheckType.REGEX_MATCHES, checking_for = r"^\s*ocredit\s*=\s*-1", in_path = Path("/etc/security/pwquality.conf")), 
            points = 5, desc = "Password must have 1 uppercase, 1 lowercase, 1 digit, and 1 special character"
        ),

        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for="NOPASSWD", in_path=Path("/etc/sudoers")), points=5, desc="Password required for sudo"),
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