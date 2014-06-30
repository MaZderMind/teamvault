from django.contrib import admin
from django.utils.translation import ugettext_lazy as _
from guardian.admin import GuardedModelAdmin

from .models import AccessRequest, Password, PasswordRevision


class AccessRequestAdmin(GuardedModelAdmin):
    fieldsets = (
        (_("Subject"), {
            'fields': (
                'requester',
                'password',
                'created',
                'reason_request',
            ),
        }),
        (_("Status"), {
            'fields': (
                'reviewers',
                'status',
                'closed',
                'closed_by',
                'reason_rejected',
            ),
        }),
    )
    date_hierarchy = 'created'
    list_display = ('requester', 'password', 'status', 'created')
    list_filter = ('status',)
    readonly_fields = ('created',)
    search_fields = ('requester__username', 'password__name',)

admin.site.register(AccessRequest, AccessRequestAdmin)


class PasswordAdmin(GuardedModelAdmin):
    fieldsets = (
        (None, {
            'fields': (
                'name',
                'id_token',
                'description',
            ),
        }),
        (_("Audit"), {
            'fields': (
                'created',
                'last_read',
            ),
        }),
        (_("Security"), {
            'fields': (
                'status',
                'access_policy',
                'needs_changing_on_leave',
            ),
        }),
    )
    date_hierarchy = 'created'
    list_display = ('name', 'id_token', 'last_read')
    list_filter = ('access_policy', 'needs_changing_on_leave', 'status')
    radio_fields = {
        'access_policy': admin.HORIZONTAL,
        'status': admin.HORIZONTAL,
    }
    readonly_fields = ('created', 'last_read', 'id_token')
    search_fields = ('name', 'description')

admin.site.register(Password, PasswordAdmin)


class PasswordRevisionAdmin(GuardedModelAdmin):
    fieldsets = (
        (None, {
            'fields': (
                'password',
                'encrypted_password',
            ),
        }),
        (_("Audit"), {
            'fields': (
                'created',
                'set_by',
                'accessed_by',
            ),
        }),
    )
    date_hierarchy = 'created'
    list_display = ('password', 'id', 'created')
    readonly_fields = ('accessed_by', 'created', 'set_by')
    search_fields = ('password__name',)

admin.site.register(PasswordRevision, PasswordRevisionAdmin)
