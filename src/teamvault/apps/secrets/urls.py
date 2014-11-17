from django.conf.urls import patterns, url
from django.contrib.auth.decorators import login_required
from django.views.generic import TemplateView

from . import views

urlpatterns = patterns('',
    url(
        r'^$',
        login_required(TemplateView.as_view(template_name="secrets/dashboard.html")),
        name='dashboard',
    ),
    url(
        r'^secrets/$',
        login_required(views.SecretList.as_view()),
        name='secrets.secret-list',
    ),
    url(
        r'^secrets/(?P<pk>\d+)$',
        login_required(views.SecretDetail.as_view()),
        name='secrets.secret-detail',
    ),
    url(
        r'^secrets/(?P<pk>\d+)/delete$',
        views.secret_delete,
        name='secrets.secret-delete',
    ),
    url(
        r'^secrets/(?P<pk>\d+)/edit$',
        login_required(views.SecretEdit.as_view()),
        name='secrets.secret-edit',
    ),
    url(
        r'^secrets/add/(?P<content_type>\w+)$',
        login_required(views.SecretAdd.as_view()),
        name='secrets.secret-add',
    ),
    url(
        r'^secrets/live-search$',
        views.live_search,
        name='secrets.live-search',
    ),
)
