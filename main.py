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
        # phorensixs
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^ANSWER:\s*spiritofthescarf\s*$", in_path = Path("/home/sebastian/Desktop/Ticket-1.txt")), points = 14, desc = "Correct response to Ticket 1"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^ANSWER:\s*making_more_propogandaa\s*$", in_path = Path("/home/sebastian/Desktop/Ticket-2.txt")), points = 8, desc = "Correct response to Ticket 2"),

        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^ANSWER:\s*7772\s*$", in_path = Path("/home/sebastian/Desktop/Ticket-4.txt")), points = 4, desc = "Correct response to Ticket 4"),

        # user/group
        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for = "mmarana", in_path = Path("/etc/group")), points = 3, desc = "Remove unauthorized user mmarana"),
        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for = "mtampus", in_path = Path("/etc/group")), points = 3, desc = "Remove unauthorized user mtampus"),
        Vuln(
            Answer(CheckType.REGEX_NO_MATCH, checking_for = r"^adm.+abossle.+", in_path = Path("/etc/group")),
            Answer(CheckType.REGEX_NO_MATCH, checking_for = r"^sudo.+abossle.+", in_path = Path("/etc/group")),
            points = 3, desc = "Removed unauthorized admin abossle"
        ),
        Vuln(
            Answer(CheckType.REGEX_NO_MATCH, checking_for = r"^current.+mdallas.+", in_path = Path("/etc/group")),
            Answer(CheckType.REGEX_MATCHES, checking_for = r"^alumni.+mdallas.+", in_path = Path("/etc/group")),
            points = 3, desc = "Changed appropriate groups for user mdallas"
        ),
        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for = "cbaummer:$y$j9T$bFMpxRP8oK5.ivpj29cO", in_path = Path("/etc/shadow")), points = 2, desc = "Change insecure password for cbaummer"),
        Vuln(Answer(CheckType.PATH_GONE, in_path=Path("/home/cbaummer/.plist")), points=2, desc="Removed unwanted file"),

        # sudoers
        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for = "NOPASSWD", in_path = Path("/etc/sudoers")), points = 3, desc = "Sudo requires password for all admins"),

        # ftp
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^anonymous_enable=NO", in_path = Path("/etc/vsftpd.conf")), points = 5, desc = "Anonymous users disabled on FTP server"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^ssl_enable=YES", in_path = Path("/etc/vsftpd.conf")), points = 5, desc = "SSL enabled on FTP server"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^chroot_local_user=YES", in_path = Path("/etc/vsftpd.conf")), points = 5, desc = "Users are chrooted on FTP server"),

        # ssh
        Vuln(
            Answer(CheckType.REGEX_MATCHES, checking_for = r"^Port 22", in_path = Path("/etc/ssh/sshd_config")), 
            Answer(CheckType.REGEX_NO_MATCH, checking_for = r"^Port 7772", in_path = Path("/etc/ssh/sshd_config")), 
            points = 2, desc = "Fixed incorrect SSH port number"
        ),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^StrictModes yes", in_path = Path("/etc/ssh/sshd_config")), points = 5, desc = "SSH Strict modes enabled"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^PermitRootLogin no", in_path = Path("/etc/ssh/sshd_config")), points = 5, desc = "SSH root login disabled"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^X11Forwarding no", in_path = Path("/etc/ssh/sshd_config")), points = 5, desc = "SSH X11 forwarding disabled"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^PermitEmptyPasswords no", in_path = Path("/etc/ssh/sshd_config")), points = 5, desc = "Empty passwords are not permitted for SSH"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^UsePAM yes", in_path = Path("/etc/ssh/sshd_config")), points = 5, desc = "SSH uses PAM"),

        # login.defs
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^PASS_MAX_DAYS\s+90", in_path = Path("/etc/login.defs")), points = 2, desc = "Password maximum age is set to 90 days"),
        
        # pam
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^\s*minlen\s*=\s*12", in_path = Path("/etc/security/pwquality.conf")), points = 4, desc = "Password must be at least 12 characters in length"),
        Vuln(
            Answer(CheckType.REGEX_MATCHES, checking_for = r"^\s*dcredit\s*=\s*-1", in_path = Path("/etc/security/pwquality.conf")), 
            Answer(CheckType.REGEX_MATCHES, checking_for = r"^\s*ucredit\s*=\s*-1", in_path = Path("/etc/security/pwquality.conf")), 
            Answer(CheckType.REGEX_MATCHES, checking_for = r"^\s*lcredit\s*=\s*-1", in_path = Path("/etc/security/pwquality.conf")), 
            Answer(CheckType.REGEX_MATCHES, checking_for = r"^\s*ocredit\s*=\s*-1", in_path = Path("/etc/security/pwquality.conf")), 
            points = 4, desc = "Password must have 1 uppercase, 1 lowercase, 1 digit, and 1 special character"
        ),
        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for = "nullok", in_path = Path("/etc/pam.d/common-password")), points = 5, desc = "Null passwords are not allowed"),

        # ufw
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^ENABLED=yes", in_path = Path("/etc/ufw/ufw.conf")), points = 3, desc = "UFW is enabled"),
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for = r"^LOGLEVEL=high", in_path = Path("/etc/ufw/ufw.conf")), points = 3, desc = "UFW logging set to high"),

        # annoyances
        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for = "apt install -y -qq x11vnc >/dev/null 2>&1", in_path = Path("/etc/crontab")), points = 4, desc = "Malicious cron job removed"),
        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for="alias nano=", in_path = Path("/etc/profile.d/20-startup.sh")), points = 4, desc = "Malicious alias removed"),

        # malware/unwanted services
        Vuln(Answer(CheckType.SERVICE_DOWN, checking_for="apache2"), points = 6, desc = "Apache2 service removed or disabled"),
        Vuln(Answer(CheckType.PATH_GONE, in_path=Path("/bin/x11vnc")), points = 6, desc = "Unwanted software x11vnc removed"),
    

        # sysctl
        Vuln(Answer(CheckType.REGEX_MATCHES, checking_for=r"^net.ipv4.conf.all.accept_source_route = 0", in_path=Path("/etc/shadow")), points = 6, desc = "System does not accept source route"),

        # permission settings
        Vuln(Answer(CheckType.PERMS_OCTAL, checking_for="600", in_path=Path("/etc/shadow")), points = 6, desc = "Correct permissions set for /etc/shadow"),
        Vuln(Answer(CheckType.PERMS_OCTAL, checking_for="644", in_path=Path("/etc/passwd")), points = 6, desc = "Correct permissions set for /etc/passwd"),
        Vuln(Answer(CheckType.PERMS_OCTAL, checking_for="1777", in_path=Path("/tmp")), points = 7, desc = "Stickybit set for /tmp"),

        # firefox
        Vuln(Answer(CheckType.STRING_NOT_FOUND, checking_for='"browser.safebrowsing.malware.enabled", false', in_path=Path("/home/sebastian/.mozilla/firefox/8p4igdi0.default-release/prefs.js")),
            points=5, desc="Safe browsing malware checks enabled in Firefox"
        ),
        Vuln(Answer(CheckType.STRING_FOUND, checking_for='"privacy.donottrackheader.enabled", true', in_path=Path("/home/sebastian/.mozilla/firefox/8p4igdi0.default-release/prefs.js")),
            points=5, desc="Do not track header enabled in Firefox"
        )
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