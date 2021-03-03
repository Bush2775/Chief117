# Using zeek-cut, we could combine multiple log files into one single file
#!/bin/sh

# Simple printout of log files
cat [log_file1] [log_file2] | zeek-cut
