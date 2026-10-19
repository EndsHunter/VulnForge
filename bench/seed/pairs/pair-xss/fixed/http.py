from html import escape


def render_name(name):
    return "<p>Hello " + escape(name) + "</p>"
