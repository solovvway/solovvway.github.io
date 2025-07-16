---
title: About Me
layout: index.njk
---

# About Me

Hi, I'm [Your Name]! This is my personal blog where I share my thoughts and experiences.

## Blog Posts

{% for post in collections.posts %}
- [{{ post.data.title }}]({{ post.url }})
{% endfor %}