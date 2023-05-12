# 从仓库拉取 带有 python 3.7 的 Alpine Linux 环境
FROM python:3.7-alpine

# 作者信息
LABEL "author"="secyun.org"

# 构建参数，工作目录
ENV PROJECT_DIR=/app

RUN mkdir -p $PROJECT_DIR
WORKDIR $PROJECT_DIR

ENV APP_PORT=8839

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

# 安装alpine依赖， system update\ mysqlclient\ system lib\ Pillow\ bash
RUN apk update \
    && apk add --virtual mysqlclient-build gcc python3-dev musl-dev \
    && apk add --no-cache mariadb-dev \
    && apk add --virtual system-build linux-headers libffi-dev \
    && apk add --no-cache jpeg-dev zlib-dev freetype-dev lcms2-dev openjpeg-dev tiff-dev tk-dev tcl-dev libxslt-dev \
    && apk add --no-cache openssh-client \
    && pip install pip -U -i https://pypi.douban.com/simple

# 为容器创建公私钥
RUN mkdir /root/.ssh \
    && chmod 700 /root/.ssh

ADD configs/id_rsa /root/.ssh/
ADD configs/id_rsa.pub /root/.ssh/

RUN chmod 644 /root/.ssh/id_rsa.pub \
    && chmod 600 /root/.ssh/id_rsa

# 将 requirements.txt 复制到容器的 / 目录
# 将当前目录复制到容器的 code 目录
#ADD . $PROJECT_DIR 
ADD requirements.txt /
RUN pip install -r /requirements.txt -i https://pypi.douban.com/simple


# 在Alpine上，pip将从源代码构建需要依赖包来install，如mysqlclient需要gcc和musl-dev，因此需要将apk del *-build推迟到安装Python模块之后
RUN apk del mysqlclient-build \
    && apk del system-build

ADD entrypoint.sh /
RUN chmod 775 /entrypoint.sh 
ENTRYPOINT ["./entrypoint.sh"]

EXPOSE $APP_PORT
CMD ["dongcha-waf-agent"]
