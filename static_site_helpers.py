import os
from flask import Flask, current_app, send_from_directory, abort
from werkzeug.security import safe_join

app = Flask(__name__)
with app.app_context():
    static_site_directory = current_app.config.get('STATIC_SITE_DIRECTORY', 'static_site')

def proxy_static_site(p):
    pair = file_path(parse_path(p))
    safe_path = safe_join('static_site', pair[0])
    if safe_path is None:
        abort(404)
    return send_from_directory(safe_path, pair[1])

def file_path(parsed_path):
    '''
        Returns a tuple with the first element equal to a path, and the
        second element equal to a file name. Suitable for passing to
        flask.safe_join and then flask.send_from_directory. (Do not pass
        straight to flask.send_file or similar!)

        If a file with an extension is requested, returns the path
        and filename unaltered.

        Otherwise, returns the full path and'index.html' as the filename.
    '''
    if parsed_path == ('',''):
        return ('', 'index.html')
    elif '.' in parsed_path[1]:
        return (parsed_path[0], parsed_path[1])
    elif parsed_path[0]:
        return ('{}/{}'.format(parsed_path[0], parsed_path[1]), 'index.html')
    else:
        return (parsed_path[1], 'index.html')

def parse_path(path):
    '''
        The domain root returns empty a pair of empty strings
        parse_path('')
        ('', '')

        Anything deeper that the domain root will have at least a slash in the
        first element of the tuple. Trailing slashes appended to the path are ignored

        parse_path('hi')
        ('', 'hi')
        parse_path('hi/')
        ('', 'hi')

        parse_path('path/to/what/i/want')
        ('path/to/what/i', 'want')
        parse_path('path/to/what/i/want/')
        ('path/to/what/i', 'want')

        If a file with an extension is requested, the second element of the tuple
        will contain a dot.

        parse_path('want.css')
        ('path/to/what/i', 'want.css')
        parse_path('/path/to/what/i/want.css')
        ('path/to/what/i', 'want.css')
    '''
    return os.path.split(path.rstrip('/'))
