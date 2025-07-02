from vulnclasses import Answer, Vuln, VulnList

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
        Vuln(Answer("regex_match_file", checking_for = r"^anonymous_enable=NO$", in_path = Path("/etc/vsftpd.conf")), points = 5, desc = "Anonymous users disabled on FTP server"),
        Vuln(Answer("regex_match_file", checking_for = r"^ssl_enable=YES$", in_path = Path("/etc/vsftpd.conf")), points = 5, desc = "SSL enabled on FTP server"),
        Vuln(Answer("regex_match_file", checking_for = r"^chroot_local_user=YES$", in_path = Path("/etc/vsftpd.conf")), points = 5, desc = "Users are chrooted on FTP server"),

        Vuln(
            Answer("regex_match_file", checking_for = r"^Port 22$", in_path = Path("/etc/ssh/sshd_config")), 
            Answer("regex_miss_file", checking_for = r"^Port 7772$", in_path = Path("/etc/ssh/sshd_config")), 
            points = 2, desc = "Fixed incorrect SSH port number"
        ),
        Vuln(Answer("regex_match_file", checking_for = r"^StrictModes yes$", in_path = Path("/etc/ssh/sshd_config")), points = 5, desc = "SSH Strict modes enabled"),
        Vuln(Answer("regex_match_file", checking_for = r"^PermitRootLogin no$", in_path = Path("/etc/ssh/sshd_config")), points = 5, desc = "SSH root login disabled"),
        Vuln(Answer("regex_match_file", checking_for = r"^X11Forwarding no$", in_path = Path("/etc/ssh/sshd_config")), points = 5, desc = "SSH X11 forwarding disabled"),
        Vuln(Answer("regex_match_file", checking_for = r"^PermitEmptyPasswords yes$", in_path = Path("/etc/ssh/sshd_config")), points = 5, desc = "Empty passwords are not permitted for SSH"),
        Vuln(Answer("regex_match_file", checking_for = r"^UsePam yes$", in_path = Path("/etc/ssh/sshd_config")), points = 5, desc = "SSH uses PAM")
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
                    Label(f"{i.points} pts: {i.desc}")
                )
            )

    def on_ready(self) -> None:
        self.action_update_score()
        self.set_interval(30, self.action_update_score, name = "refresher")


if __name__ == "__main__":
    app = Module()
    app.run()