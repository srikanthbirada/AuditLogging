while(1) {
	my $time = time;
	`echo "$time : Filebeat is alive" >>/sc/filebeat/heartbeat.log`;
	sleep(60);
}
