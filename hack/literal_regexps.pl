#!/usr/bin/env perl
# literal_regexps.pl rewrites the text patterns of constrained rules as literal
# regexps, in place. A rule is constrained when its condition bounds filesize
# or the file header (uint16(0) == 0x5A4D, $a at 0).
#
# yara-x 1.20.0 assigns one pattern ID to every rule that declares the same
# text pattern, but records the filesize bounds and header constraints of the
# first declaring rule only. The scanner then disables that pattern for every
# rule whenever the file falls outside those constraints, so a rule with no
# size limit stops matching small or large files and a negated pattern turns
# into a false positive. Regexp and hex patterns carry their constraints in
# the pattern identity and are unaffected, and a regexp made only of literal
# bytes compiles to the same literal matcher as a text pattern.
#
# Patterns with xor, base64, or base64wide modifiers cannot be expressed as
# regexps and are left alone.
#
# Usage: literal_regexps.pl FILE...
use strict;
use warnings;

my %allowed = map { $_ => 1 } qw(ascii wide nocase fullword private);

# text_to_regexp converts the body of a YARA text pattern (the bytes between
# the quotes, with YARA escapes) to an equivalent regexp body. Returns undef
# when the body contains an escape sequence it does not understand.
sub text_to_regexp {
	my ($body) = @_;
	my $re = '';
	while (length $body) {
		if ($body =~ s/^\\x([0-9A-Fa-f]{2})//) { $re .= "\\x$1"; next; }
		if ($body =~ s/^\\([tnr])//)          { $re .= "\\$1"; next; }
		if ($body =~ s/^\\"//)                { $re .= '"'; next; }
		if ($body =~ s/^\\\\//)               { $re .= '\\\\'; next; }
		return undef if $body =~ /^\\/;
		$body =~ s/^(.)//s;
		my $c = $1;
		if ($c =~ m{[\\/.^\$|?*+()\[\]{}]}) {
			$re .= "\\$c";
		} elsif (ord($c) < 0x20 || ord($c) > 0x7e) {
			$re .= sprintf('\\x%02X', ord $c);
		} else {
			$re .= $c;
		}
	}
	return $re;
}

# rewrite_line converts one `$name = "text" modifiers` line. Lines that are
# not text patterns, or that carry unsupported modifiers, are returned as is.
sub rewrite_line {
	my ($line) = @_;
	return $line
	  unless $line =~ /^(\s*\$\w*\s*=\s*)"((?:[^"\\]|\\.)*)"(.*?)(\r?\n?)$/s;
	my ($lhs, $body, $rest, $eol) = ($1, $2, $3, $4);
	my ($mods) = $rest =~ m{^(.*?)(?://.*|/\*.*)?$}s;
	for my $mod (split ' ', $mods) {
		return $line unless $allowed{$mod};
	}
	my $re = text_to_regexp($body);
	return $line unless defined $re;
	return "$lhs/$re/$rest$eol";
}

# constrained reports whether a condition can yield filesize bounds or header
# constraints: it mentions filesize, reads an integer at a file offset, or
# anchors a pattern with `at`. Matching more conditions than strictly needed
# is harmless.
sub constrained {
	my ($cond) = @_;
	return $cond =~ /\bfilesize\b/
	  || $cond =~ /\bu?int(?:8|16|32)(?:be)?\s*\(/
	  || $cond =~ /\bat\s/;
}

# rewrite_rules applies rewrite_line to the strings section of every
# constrained rule. Rules start at a `rule` header and end at a `}` in column
# zero.
sub rewrite_rules {
	my ($lines) = @_;
	my ($in_rule, $section, $cond, @strings) = (0, '', '');
	my $flush = sub {
		if (constrained($cond)) {
			$lines->[$_] = rewrite_line($lines->[$_]) for @strings;
		}
		($in_rule, $section, $cond, @strings) = (0, '', '');
	};
	for my $i (0 .. $#$lines) {
		my $l = $lines->[$i];
		if (!$in_rule) {
			$in_rule = 1
			  if $l =~ /^\s*(?:(?:private|global)\s+)*rule\s+\w+/;
			next;
		}
		if ($l =~ /^\}\s*$/) { $flush->(); next; }
		if ($l =~ /^\s*(meta|strings|condition)\s*:(.*)$/s) {
			$section = $1;
			$cond .= $2 if $section eq 'condition';
			next;
		}
		if    ($section eq 'strings')   { push @strings, $i; }
		elsif ($section eq 'condition') { $cond .= $l; }
	}
	$flush->() if $in_rule;
}

for my $file (@ARGV) {
	open(my $in, '<:raw', $file) or die "open $file: $!";
	my @lines = <$in>;
	close $in;
	my $before = join '', @lines;
	rewrite_rules(\@lines);
	my $after = join '', @lines;
	next if $after eq $before;
	open(my $out, '>:raw', $file) or die "write $file: $!";
	print $out $after;
	close $out;
}
