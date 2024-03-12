use strict;
use warnings;
use Getopt::Long;
use Crypt::OpenSSL::RSA;
use Time::HiRes qw(gettimeofday tv_interval clock_gettime);

sub help_msg {
    print << "END";
timing.pl -i file -o file -k file -n size

-i file      File with the ciphertexts to decrypt
-o file      File to write the timing data to
-k file      The private key to use for decryption
-n size      Size of individual ciphertexts for decryption
-h | --help  this message
END
}

my ($in_file, $out_file, $key_file, $read_size);

my $result = GetOptions(
    "i=s" => \$in_file,
    "o=s" => \$out_file,
    "k=s" => \$key_file,
    "n=i" => \$read_size,
    "h|help" => \&help_msg
);

unless ($in_file && $out_file && $key_file && $read_size) {
    die "ERROR: Missing parameters.\n";
}

my $rsa = Crypt::OpenSSL::RSA->new_private_key(
    do {
        local $/;
        open my $fh, "<", $key_file or die "Failed to open key file: $!";
        <$fh>;
    }
);
$rsa->use_pkcs1_padding();

open my $in_fh, "<", $in_file or die "Failed to open input file: $!";
open my $out_fh, ">", $out_file or die "Failed to open output file: $!";

print $out_fh "raw times\n";

while (1) {
    my $ciphertext;
    my $bytes_read = read($in_fh, $ciphertext, $read_size);
    last unless $bytes_read;

    my $t0 = clock_gettime(7); # CLOCK_BOOTTIME

    eval {
        my $plaintext = $rsa->decrypt($ciphertext);
    };

    my $elapsed = clock_gettime(7) - $t0;

    my $date = sprintf "%.9f", $elapsed;
    print $out_fh "$date\n";
}

close $in_fh;
close $out_fh;

print "done\n";

