table_lowercase = "abcdefghijklmnopqrstuvwxyz"
table_uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
table_digits = "0123456789"
table_symbols = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
table_alphanumeric = table_lowercase + table_uppercase + table_digits
table_printable = table_alphanumeric + table_symbols

# Character table frequently used for flag
table_small = "_-" + table_alphanumeric + "{} "
table_medium = "_-" + table_alphanumeric + "{}!?$+=@.,/ "
table_large = "_-" + table_alphanumeric + "{}!?$+=@.,/'#%&*()<>:;|^~` "
