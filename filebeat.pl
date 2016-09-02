#!/usr/bin/env perl
use strict;
use Time::Local;
use POSIX;
use Getopt::Long qw(GetOptions);


my %timezone_lookuphash = ("-09:30"=>"Pacific/Marquesas",
"-04:30"=>"America/Caracas",
"-03:30"=>"America/St_Johns",
"+03:30"=>"Asia/Tehran",
"+04:30"=>"Asia/Kabul",
"+05:30"=>"Asia/Colombo",
"+06:30"=>"Asia/Rangoon",
"+05:45"=>"Asia/Kathmandu",
"+09:30"=>"Australia/Adelaide",
"+10:30"=>"Australia/Lord_Howe",
"+11:30"=>"Pacific/Norfolk",
"+08:45"=>"Australia/Eucla",
"+12:45"=>"Pacific/Chatham");

sub getTypeName {
	my $file = $_[0];
	my $type;
	if ($file =~ /messages/){
		$type = "messages";
	}
	elsif($file =~ /zscaler.log/ ){
		$type = "zscalerlog";
	}
	elsif($file =~ /bash_history/ ){
		$type = "bashhistory";
	}
	elsif($file =~ /install.log/ ){
		$type = "installog";
	}
	elsif($file =~ /run.log/ ){
		$type = "spmlog";
	}
	elsif($file =~ /setcainfo.log/ ){
		$type = "setcainfo";
	}
	elsif($file =~ /smsm_cluster_mgmt.log/ ){
		$type = "smsmclustermgmt";
	}
	elsif($file =~ /racoon.log/ ){
		$type = "smsmcounters";
	}
	elsif($file =~ /smstat.log/ ){
		$type = "smstat"
	}
	elsif($file =~ /query.log/ ) {
		$type = "zqlquery";
	}
	else {
		$type = "NotKnown";
	}
	return $type;
}

sub convert_toepochtime {
    my $datetime = $_[0];
    my %month;
    @month{ qw/Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec/ } = 0..11;
    my ($day, $mon,$date,$hr,$min,$sec,$yr) = split (/\W+/,$datetime);
    my $time = timelocal($sec, $min, $hr, $date, $month{$mon}, $yr);
    return $time;
}


sub getCloudName {
	my $cloudname;
	if (-e "/sc/conf/.cloudname") {
    	$cloudname = `cat /sc/conf/.cloudname`;
	  	chomp($cloudname);
	}
	else {
        my $hostname= `hostname`;
        chomp($hostname);
        my $inst= "$hostname"."1-sme";
        if (-e "/sc/$inst/conf/.cloudname") {
            $cloudname= `cat /sc/$inst/conf/.cloudname`;
            chomp($cloudname);
        }
        else {
            $cloudname = "zscaler";
        }
    }
	return $cloudname;
}

sub getLocalIp {
	my $result = `ifconfig | grep inet`;
    my @lines = split("\n",$result);
    my @keys = split(" ",$lines[1]);
    return $keys[1];
}

sub getTimeAdjust {
	my $time = (localtime);
    my $gmt = (gmtime);
    my $sign;
    my $timezone;
    my $localepochtime = convert_toepochtime($time);
    my $gmtepochtime = convert_toepochtime($gmt);
    my $diff ;
    my $printsign;
    if ($gmtepochtime < $localepochtime) {
        $sign = "+";
        $printsign= "-";
        $diff =$localepochtime - $gmtepochtime;
    }
    else {
        $sign = "-";
        $printsign= "+";
        $diff =$gmtepochtime - $localepochtime;
    }
    my $hour = $diff/3600;
    $hour = floor($hour);
    my $ses = $diff%3600;
    my $min = $ses/60;
    if ($min == 0) {
        $timezone = "Etc/GMT$printsign$hour";
    }
    else {
        $hour = "0$hour" if ($hour <10);
        $timezone= $timezone_lookuphash{"$sign$hour:$min"};
    }
	return $timezone;
}

sub createConfigFile {
	#Getting all the required variables for modifying config file;#
	my $fileslist = $_[0];
	my $serverlist = $_[1];
	my $cloudname = getCloudName();
	my $localip = getLocalIp();
	my $timeadjust = getTimeAdjust();
	####
	#Reading from sample.yml file and writing into final.yml by modifying all the above mentioned variables;#
	open READ, "<sample.yml";
	my @lines = <READ>;
	open WRITE, ">filebeat.yml";
	print WRITE $lines[0];
	print WRITE $lines[1];
	####
	#modifying the prospectors part, writing for each file#
	my @files = split(",",$fileslist);
	foreach my $file(@files){
		my $type = getTypeName($file);
		my $i;
		for ($i = 2; $i <= 9 ; $i++){
			if ( $lines[$i] =~ /::localipaddress/ ){
				my $line = $lines[$i];
				$line =~ s/::localipaddress/$localip/g;
				print WRITE $line;
			}
			elsif ( $lines[$i] =~ /::cloudname/ ) {
				my $line = $lines[$i];
				$line =~ s/::cloudname/$cloudname/g;
				print WRITE $line;
			}
			elsif ( $lines[$i] =~ /::filepath/ ) {
				my $line = $lines[$i];
				$line =~ s/::filepath/$file/g;
				print WRITE $line;
			}
			elsif ($lines[$i] =~ /::filetype/ ){
				my $line = $lines[$i];
				$line =~ s/::filetype/$type/g;
				$line =~ s/::timeadjust/$timeadjust/g;
				print WRITE $line;
			}
			else {
				print WRITE $lines[$i];
			}
		}
	}
	####
	#Writing remaining lines including output part#	
	#Getting serverslist#
	##Getting certificate list##
	#my $certlist = "";
	my @servers = split(",",$serverlist);
=head
	foreach my $server ( @servers ) {
		my $certificate = "/sc/filebeat/".substr($server, 0, -4).".crt";
		if( !(-e "$certificate") ){
        	print "Authentication certificate for given logstash server doesn't exist\n";
         	return 1;
    	}
    	$certlist = $certlist.$certificate.',';
	}
=cut
	#chop($certlist);
	#$certlist =~ s/,/","/g;
	####
	$serverlist =~ s/,/","/g;
	my $j;
	for ($j = 10; $j <= 26; $j++){
		if ($lines[$j] =~ /::serveripaddress/ ) {
			$lines[$j] =~ s/::serveripaddress/"$serverlist"/g;
		}
=head
		if ( $lines[$j] =~ /::sslcertificate/){
			$lines[$j] =~ s/::sslcertificate/"$certlist"/g;
		}
=cut
		print WRITE $lines[$j];
	}
	return 0;
}

sub start {
	my $status = status();
	if($status) {
		system("/sc/filebeat/filebeat-freebsd-amd64 -c /sc/filebeat/filebeat.yml & ");
    	return $?;
	}
	else {
		print "Filebeat is already running\n";
		return 1;
	}
}

sub stop {
	my $status = status();
	if($status) {
		print "Filebeat is not running\n";
		return 1;
	}
	else {
    	`pkill filebeat`;
    	return $?;
	}
}

sub status {
	my $pid = `pgrep filebeat`;
	return !$pid;
}

MAIN: {
	my $time = localtime;
    open logger, ">>/sc/filebeat/filebeat.log";
	my $fileslist;
	my $serverlist;
	GetOptions(
		'files=s' => \$fileslist,
		'serverips=s' => \$serverlist,
	) or die "Usage: $0 --files  --serverips\n";
	if ( scalar @ARGV == 1 ) {
		if ($ARGV[0] eq "configure"){	
			my $status = createConfigFile($fileslist,$serverlist);
			if ( $status ){
				print "Configuration Failed\n";
			}
			else {
				print "Configuration Successful\n";
			}
		}
		elsif ($ARGV[0] eq "start"){
			my $status = start();
			if ( $status ){
				print logger "$time : Filebeat Start Failed\n";
				print "Filebeat Start Failed\n";
				exit;
			}
			else {
				print logger "$time : Filebeat Start Successful\n";
				print "Filebeat Start Successful\n";
				exit;
			}
		}
		elsif ($ARGV[0] eq "stop"){
			my $status = stop();
			if ( $status ){
				print logger "$time : Filebeat Stop Failed\n";
				print "Filebeat Stop failed\n";
				exit;
			}
			else {
				print logger "$time : Filebeat Stop Successful\n";
				print "Filebeat Stop Successful\n";
			}
		}
		elsif ($ARGV[0] eq "status"){
			my $status = status();
			if ( $status ){
				print "Filebeat is not running\n";
			}
			else {
				print "Filebeat is already running\n";
			}
		}
		elsif ($ARGV[0] eq "cleanrestart"){
			my $status = status();
			if( $status ){
				if ( -e "/sc/filebeat/.filebeat" ){
					system("rm /sc/filebeat/.filebeat");
            		if($?) {
						print logger "$time : Removing /sc/filebeat/.filebeat failed\n";
                		print "Removing /sc/filebeat/.filebeat failed\n";
                		exit;
            		}
				}
				$status = start();
				if ( $status ) {
					print logger "$time : Filebeat Start Failed\n";
					print "Filebeat start failed\n";
					exit;
				}
				else {
					print logger "$time : Filebeat Clean Restart Successful\n";
					print "Filebeat clean restart successful\n";
					exit;
				}
			}
			else {
				$status = stop();
            	if ($status) {
					print logger "$time : Filebeat Stop Failed\n";
               	 	print "Filebeat stop failed\n";
                	exit;
            	}
				if ( -e "/sc/filebeat/.filebeat" ){
					system("rm /sc/filebeat/.filebeat");
            		if($?) {
						print logger "$time : Removing /sc/filebeat/.filebeat Failed\n";
                		print "Removing /sc/filebeat/.filebeat failed\n";
                		exit;
            		}
				}
            	$status = start();
            	if ($status) {
					print logger "$time : Filebeat Start Failed\n";
                	print "Filebeat start failed\n";
                	exit;
            	}
            	else {
					print logger "$time : Filebeat Clean Restart Successful\n";
                	print "Filebeat clean restart successful\n";
                	exit;
            	}
			}
		}
		elsif ($ARGV[0] eq "restart") {
            my $status = status();
            if ($status) {
				$status = start();
            	if ($status) {
					print logger "$time : Filebeat Start Failed\n";
               	 	print "Filebeat start failed\n";
                	exit;
            	}
            	else {
					print logger "$time : Filebeat Restart Successful\n";
                	print "Filebeat Restart succesful\n";
                	exit;
            	}
			}
			$status = stop();
			if ($status) {
				print logger "$time : Filebeat Stop Failed\n";
                print "Filebeat stop failed\n";
                exit;
            }
			else {
				$status = start();
            	if ($status) {
					print logger "$time : Filebeat Start Failed\n";
               	 	print "Filebeat start failed\n";
                	exit;
            	}
            	else {
					print logger "$time : Filebeat Restart Successful\n";
                	print "Filebeat Restart succesful\n";
                	exit;
            	}
			}
		}
		else {
			print "Incorrect Argument\nValid Options : \n\tconfigure --fileslist --serverips\n\tstart\n\tstop\n\tstatus\n\trestart\n\tcleanrestart\n";
			exit;
		}
	}
	else {
		print "Incorrect Argument\nValid Options : \n\tconfigure --fileslist --serverips\n\tstart\n\tstop\n\tstatus\n\trestart\n\tcleanrestart\n";
		exit;
	}
}
