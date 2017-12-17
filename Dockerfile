FROM python:3
MAINTAINER Chaofeng Chen <cchen1103@gmail.com>
ADD netio netio
CMD python3 -m netio
