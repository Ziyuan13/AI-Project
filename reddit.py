import praw
import json
from urllib import request

'''The reddit_instance object will contain the reddit instance we will create to handle all API calls. 
   Read the Python Reddit API Wrapper(PRAW) documentation for further details'''


def create_reddit_instance(read_only=False):
    '''This function reads the crendentials from credentials.json and creates a Reddit instance.
        You will use this instance to retrieve further information. Before you complete this
        function, make sure to create your crendentials on the Reddit website, and update
        credentials_template.json
    '''
    with open('credentials.json', 'r') as credentials_file:
        credentials = json.load(credentials_file)

    if (read_only):
        reddit_instance = praw.Reddit(client_id=credentials['client_id'],
                                      client_secret=credentials['client_secret'],
                                      username=credentials['username'],
                                      password=credentials['password'],
                                      user_agent=credentials['user_agent'])
    else:
        reddit_instance = praw.Reddit(client_id=credentials['client_id'],
                                      client_secret=credentials['client_secret'],
                                      user_agent=credentials['user_agent'])

    return reddit_instance


def ten_top_titles(reddit_instance, subreddit):
    '''This function takes a subreddit name as a string and prints out the ten latest posts
    under the hot category'''
    subreddit_instance = reddit_instance.subreddit(subreddit)
    return subreddit_instance.top(limit=10)


if __name__ == '__main__':
    reddit_instance = create_reddit_instance(read_only=False)
    ten_top_titles(reddit_instance, 'ALBA_Ewaste')


