# coding:utf-8

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '5o@#+%b-%j_-47tzsdfdsfsdfdfsd2*ie!7++=&a)%'

AGENT_KEY = 'YWNjZXNza2V5PUdycTkweDRaWFlGNWgyc0FmQ0VFOGFGZDF1WHlFZkE' \
            '3TTB4YjhyTjcmc2VjcmV0a2V5PXhHb2FwRVhUdVJjeXVXZktqV1hNdnhxdnRaajk1YTJmYk9aOHk0WmE='

# DEBUG = True
DEBUG = False

ALLOWED_HOSTS = ['*']
REGEX_URL = '{url}'  # url作严格匹配
# 设置不需要权限的页面
SAFE_URL = [
    '/view/',
    '/user/',
    '/notice/',
]

# dindding报警
DING_URL = 'https://oapi.dingtalk.com'

# 极验验证码 安全秘钥
pc_geetest_id = "7639d4190a3c3fe52adc350a67750f34"
pc_geetest_key = "9d78d5ff3c8cb5c03757sdfdsfdsfs9"

# 设置网站根地址
WEB_URL = 'http://localhost:8001'

Access_index = 'web-log-*'
Intercept_index = 'waf-log-*'

# 设置登录初始路径
LOGIN_URL = '/view/'

# 设置缓存文件路径
TMP_PATH = os.path.join(BASE_DIR, 'tmp')

# 设置登录session有效时间
SESSION_COOKIE_AGE = 60 * 360
# 设置session管理历览器失效
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# 设置上传路径
MEDIA_ROOT = os.path.join(BASE_DIR, 'files')
MEDIA_URL = "/uploads/"

# 定义session 键：
# 保存用户权限url列表
# 保存 权限菜单 和所有 菜单
SESSION_PERMISSION_URL_KEY = 'spuk'
SESSION_MENU_KEY = 'smk'
ALL_MENU_KEY = 'amk'
PERMISSION_MENU_KEY = 'pmk'

# 设置队列存储
# BROKER_URL = 'redis://:xxxxxxxx@127.0.0.1:6379'
CELERY_ACCEPT_CONTENT = ['pickle', 'json', 'msgpack', 'yaml']

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'RBAC',
    'RuleManage',
    'NoticeManage',
    'SettingManage',
    'WafChartManage',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'RBAC.middleware.rbac.RbacMiddleware',
]

ROOT_URLCONF = 'SeMF.urls'

# 设置静态模板文件路径
TEMPLATE_PATH = os.path.join(BASE_DIR, 'templates')
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [TEMPLATE_PATH],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'SeMF.wsgi.application'

# Database
# https://docs.djangoproject.com/en/2.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'dongcha_waf',
        'USER': 'dongcha_waf_rw',
        'PASSWORD': '66C_7e3a384c3@F',
        'HOST': '169.254.1.5',
        'PORT': '3306',
        'OPTIONS': {
            'charset': 'utf8',
        }
    }
}
'''

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'waf',
        'USER': 'root',
        'PASSWORD': 'root',
        'HOST': '127.0.0.1',
        'PORT': '3306',
        'OPTIONS': {
            'charset': 'utf8',
        }
    }
}
'''
# Password validation
# https://docs.djangoproject.com/en/2.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/2.0/topics/i18n/
LANGUAGE_CODE = 'zh-Hans'

TIME_ZONE = 'Asia/Shanghai'

USE_I18N = True

USE_L10N = True

USE_TZ = False

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
STATICFILES_DIRS = (
    os.path.join(BASE_DIR, "static").replace('\\', '/'),
)
