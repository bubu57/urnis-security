#!/usr/bin/perl

open (SSH, "/etc/ssh/sshd_config");
while ($ssh = <SSH>) {
    if ($ssh =~ /^(\w+)\s+(.*)/) {
        if ($1 eq "PasswordAuthentication" && $2 ne "no") {
            print "L'authentification par mot de passe est autorisée pour SSH\n";
        } elsif ($1 eq "PermitRootLogin" && $2 ne "no") {
            print "La connexion root est autorisée pour SSH\n";
        }
    }
}
close (SSH);