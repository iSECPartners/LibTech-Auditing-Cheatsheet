#!/usr/bin/env python

import markdown

f_in = open('README.md', 'r')
guidelines = "".join(f_in.readlines())

md = markdown.Markdown(safe_mode='escape', extensions=['urlize'])

html = md.convert(guidelines)
html = html.replace('&lt;true_pre&gt;', '<pre>')
html = html.replace('&lt;/true_pre&gt;', '</pre>')

f_out = open('guidelines.html', 'w')
f_out.write(html)