#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# sizes.pl
# Plugin for RegRipper; traverses through a Registry hive,
# looking for values with binary data types, and checks their
# sizes; change $min_size value to suit your needs
#
# Change history
#    20180607 - modified based on Meterpreter input from Mari DeGrazia
#    20150527 - Created
# 
# copyright 2015 QAR, LLC
# Author: H. Carvey
#-----------------------------------------------------------
package sizes;
use strict;

my $min_size = 5000;

my %config = (hive          => "All",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20180607);

sub getConfig{return %config}
sub getShortDescr {
	return "Scans a hive file looking for binary value data of a min size (".$min_size.")";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();
my $count = 0;

sub pluginmain {
	my $class = shift;
	my $file = shift;
	my $reg = Parse::Win32Registry->new($file);
	my $root_key = $reg->get_root_key;
	::logMsg("Launching sizes v.".$VERSION);
	::rptMsg("sizes v.".$VERSION); 
  ::rptMsg("(".getHive().") ".getShortDescr()."\n");  
  
  my $start = time;
    
	traverse($root_key);
	
	my $finish = time;
	
	::rptMsg("Scan completed: ".($finish - $start)." seconds");
	::rptMsg("Total values  : ".$count);
}

sub traverse {
	my $key = shift;
#  my $ts = $key->get_timestamp();
  
  foreach my $val ($key->get_list_of_values()) {
  	$count++;
  	my $type = $val->get_type();
  	if ($type == 0 || $type == 3 || $type == 1 || $type == 2) {
  		my $data = $val->get_data();
			my $len  = length($data);
			if ($len > $min_size) {
				
				my @name = split(/\\/,$key->get_path());
				$name[0] = "";
				$name[0] = "\\" if (scalar(@name) == 1);
				my $path = join('\\',@name);
				::rptMsg("Key  : ".$path."  Value: ".$val->get_name()."  Size: ".$len." bytes");
#				::rptMsg("");
			}
  	}
  }
  
	foreach my $subkey ($key->get_list_of_subkeys()) {
		traverse($subkey);
  }
}

1;