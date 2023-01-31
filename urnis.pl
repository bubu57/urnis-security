#!/usr/bin/perl

$green=`tput setaf 2`;
$red=`tput setaf 1`;
$normal=`tput sgr0`;
$bleu=`tput setaf 4`;

my $test_number = 0;
my $warning_number = 0;
my $scanf = 0;
my $suspect_files = 0;

sub helper {
    printf "[ Urnis 1.0.0 ]\n\n";

    printf ("   $bleu Description $normal\n");
    printf ("       Urnis is a script that performs a security audit of your system.\n\n");

    printf ("   $bleu Usage $normal\n");
    printf ("       sudo urnis OPTION");

    printf ("\n\n   $bleu Option $normal\n");
    printf ("%-20s %-20s %s\n", "       OPTION", "NAME", "DESCRIPTION");
    printf ("%-20s %-20s %s\n", "       -a", "audit", "make audit of your system");
    printf ("%-20s %-20s %s\n", "       -h", "help", "usage of urnis");
    printf ("%-20s %-20s %s\n", "       -u", "update", "update of Urnis");
    printf ("%-20s %-20s %s\n", "       -l &", "look", "generation of an audit every 12 hours automatically");
    printf ("%-20s %-20s %s\n", "       -m", "audit mail", "make audit of your system and send it by email");
    printf ("%-20s %-20s %s\n", "       -r", "remove", "remove all files of urnis");
    printf ("%-20s %-20s %s\n", "       -k", "kill look", "kill look mode process");
    printf ("%-20s %-20s %s\n", "       -s", "status", "status of look mode");

    printf ("\n\n   $bleu Configuration $normal\n");
    printf ("%-41s %s\n", "       Configure mail", "/usr/share/urnis/src/urnis.conf");
    printf ("%-41s %-20s %s\n", "       Add programs to check", "/usr/share/urnis/src/pro.txt");
    printf ("%-41s %-20s %s\n", "       Add directories to check", "/usr/share/urnis/src/dir.txt");
    printf ("%-41s %-20s %s\n", "       Enable apt update in look mode", "/usr/share/urnis/src/urnis.conf");


    printf ("\n\n   $bleu Author $normal\n");
    printf ("%-20s %s\n", "       github", "https://github.com/bubudotsh/urnis-secutity");
    printf ("%-20s %s\n", "       developper", "BUNELIER Hugo");
    print "\n";
}

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

    execut("port",
    $cmd = `if [ -f /etc/ssh/sshd_config ] ; then grep -iE 'port' /etc/ssh/sshd_config | grep 22 ; else echo "1" ; fi`);

    execut("root login",
    $cmd = `if [ -f /etc/ssh/sshd_config ] ; then grep -iE '^PermitRootLogin' /etc/ssh/sshd_config | wc -l | grep "0" ; else echo "1" ; fi`);
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
    my $total_file = 0;
    my $suspect_file = 0;
    my $hashfile = "/usr/share/urnis/src/MD5Hahses.txt";
    my $file_path = "/usr/share/urnis/src/dir.txt";
    open(FILE, "<", $file_path) or die "Cannot open file: $!";

    while (my $line = <FILE>) {
        chomp $line;
        if (-d $line) {
            printf "%-47s", " - Checking $line";
            if (! -f $hashfile) {
                print "Hash file list not found\n";
                exit 1;
            }
            my @files = glob "$line/*";
            foreach my $file (@files) {
                if (-d $file) {
                next;
                }
                my $file_hash = `md5sum $file | cut -d' ' -f1`;
                chomp $file_hash;
                my $match = `grep $file_hash $hashfile`;
                if ($match eq '') {
                    $total_file++;
                }
                else {
                    $suspect_file++;
                }
            }
            if ($suspect_file == 0) {
                printf "$green OK $normal\n";
            }
            else {
                print "$red FOUND $normal\n";
            }
        }
        else {
            printf "%-45s %s\n", " - Checking $line", "NOT FOUND";
        }
    }

    $total_file += $suspect_file;

    close(FILE);
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
    } elsif ($arg = "h") {
        helper();
    } else {
        print "bad option";
    }
}