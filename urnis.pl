#!/usr/bin/perl

$green=`tput setaf 2`;
$red=`tput setaf 1`;
$normal=`tput sgr0`;
$bleu=`tput setaf 4`;

my $test_number = 0;
my $warning_number = 0;
my $scanf = 0;
my $suspect_files = 0;


sub affiche {
    my (@var) = @_;
    my $filename = "$var[0]";
    open (my $fh, '<', $filename);
    while (my $line = <$fh>) {
        print $line;
    }
    close $fh;
}

sub count_lines {
   my ($string) = @_;
   my @lines = split /\n/, $string;
   return scalar @lines;
}

sub execut {
    my (@var) = @_;
    my $lines = count_lines($var[1]);

    if ($lines > 0) {
        printf("%-45s %s\n", "   - $var[0]", "$red WARNING $normal $lines");
        $cmd = `echo "$var[1]" >> /usr/share/urnis/data/log 2>> /usr/share/urnis/data/log`;
        $warning_number++;
    } else {
        printf("%-45s %s\n", "   - $var[0]", "$green OK $normal");
    }
    $test_number++;
}

sub users {
    printf("\n$bleu Checking user $normal\n -----------------\n");

    execut("user with empty password",
    $cmd = `sudo getent shadow | grep ':!:' | cut -d: -f1`);

    execut("user with admin right",
    $cmd = `if [ -f /etc/sudoers ] ; then sudo cat /etc/sudoers | grep '^%admin' ; else echo "1" ; fi`);

    execut("inactive users",
    $cmd = `if [ -f /etc/shadow ] ; then sudo cat /etc/shadow | grep ":!" | awk -F ":" '{print $1}' ; else echo "1" ; fi`);
}

sub software {
    printf("\n$bleu Checking software $normal\n -----------------\n");

    execut("outdated software",
    $cmd = `apt-get dist-upgrade --dry-run | grep "^Inst" | awk '{print $2}'`);

    execut("inactive services",
    $cmd = `systemctl list-units --all --type=service | grep "inactive"`);
}

sub ssh {
    printf("\n$bleu Checking ssh $normal\n -----------------\n");

    execut("ssh port",
    $cmd = `if [ -f /etc/ssh/sshd_config ] ; then grep -iE 'port' /etc/ssh/sshd_config | grep 22 ; else echo "1" ; fi`);
}

sub boot_info {
    printf("\n$bleu Checking boot $normal\n -----------------\n");

    execut("Secure boot",
    $cmd = `mokutil --sb-state | grep "disable"`);
}

sub check {
    my $count = 0;
    my @urnis_check_files = ('/usr/share/urnis/src/MD5Hahses.txt',
'/usr/share/urnis/src/urnis.conf',
'/usr/share/urnis/src/mailsender.py',
'/usr/share/urnis/src/dir.txt');

    my @urnis_check_require = ('/etc/sudoers',
'/etc/shadow',
'/etc/ssh/sshd_config',
'/etc/os-release');

    printf("$bleu Checking files $normal\n -----------------\n");
    foreach my $files (@urnis_check_files) {
        if (-e "$files") {
            $count++;
        }
    }
    if ($count < 4) {
        printf("%-45s %s\n", "   - urnis check files", "$red WARNING $normal");
    } else {
        printf("%-45s %s\n", "   - urnis check files", "$green OK $normal");
    }

    $count = 0;
    foreach my $files (@urnis_check_require) {
        if (-e "$files") {
            $count++;
        }
    }
    if ($count < 4) {
        printf("%-45s %s\n", "   - urnis check require file", "$red WARNING $normal");
    } else {
        printf("%-45s %s\n", "   - urnis check require file", "$green OK $normal");
    }
}

sub os_detection {
    printf("\n$bleu OS detection $normal\n -----------------\n");
    $cmd = `egrep '^(NAME)=' /etc/os-release | cut -c 7- | sed 's/"//g'`;
    printf("%-45s %s", "   - System", " $cmd");
    $cmd = `egrep '^(VERSION)=' /etc/os-release | cut -c 9- | sed 's/"//g'`;
    printf("%-45s %s", "   - Version", " $cmd");
    $cmd = `uname -r`;
    printf("%-45s %s", "   - Kernel", " $cmd");
    $cmd = `hostname -I`;
    printf("%-45s %s", "   - Ip", " $cmd");
    $cmd = `hostname`;
    printf("%-45s %s", "   - Name", " $cmd");
}

sub recomanded_programs {
    printf("\n$bleu Recomanded programs $normal\n -----------------\n");
    my @recomanded_programs_list = ('ufw',
'fail2ban',
'snort',
'portsentry',
'logwatch');

    foreach my $prog (@recomanded_programs_list) {
        execut("$prog",
        $cmd = `if command -v $prog > /dev/null ; then continue ; else echo "1" ; fi`);
    }
}

sub scan {
    printf("\n$bleu check malware by MD5 $normal\n -----------------\n");
    system("/usr/share/urnis/src/scan.sh");
}

sub audit {
    $cmd = `echo "" > /usr/share/urnis/data/log`;
    check();
    os_detection();
    recomanded_programs();
    users();
    software();
    ssh();
    boot_info();
    scan();
}

foreach my $arg (@ARGV) {
    if ($arg = "a") {
        audit();
    }
}