# Password guessing notice
# @load protocols/ssh/detect-bruteforcing

# redef SSH::password_guesses_limit=10;

# hook Notice::policy(n: Notice::Info)
#     {
#     if ( n$note == SSH::Password_Guessing && /192\.168\.56\.103/ in n$sub )
#         add n$actions[Notice::ACTION_EMAIL];
#     }

# hook Notice::policy(n: Notice::Info) &priority=5
#     {
#     # Insert your code here.
#     if ( )
#         add n$actions[Notice::ACTION_EMAIL];
#     }
