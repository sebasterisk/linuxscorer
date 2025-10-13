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
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for=r"^1$", in_path=Path("/proc/sys/net/ipv4/conf/default/rp_filter")), points = 5, desc = "IP forwarding disabled"), 
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for=r"^0$", in_path=Path("/proc/sys/net/ipv4/ip_forward")), points = 5, desc = "IP forwarding disabled"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for=r"^0$", in_path=Path("/proc/sys/net/ipv4/conf/all/accept_redirects")), points = 5, desc = "ICMP redirects disabled"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for=r"^0$", in_path=Path("/proc/sys/net/ipv4/conf/all/accept_source_route")), points = 5, desc = "I am not a router!!"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for=r"^1$", in_path=Path("/proc/sys/net/ipv4/conf/all/log_martians")), points = 5, desc = "Martian packets logged"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for=r"^1$", in_path=Path("/proc/sys/net/ipv4/icmp_echo_ignore_all")), points = 5, desc = "Ignores pings"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for=r"^1$", in_path=Path("/proc/sys/net/ipv4/tcp_rfc1337")), points = 5, desc = "TIME-WAIT assassination measures enabled"),
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