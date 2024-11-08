from django.contrib import admin
from .models import User, Assignment, AssignmentSubmission

admin.site.register(User)
admin.site.register(Assignment)
admin.site.register(AssignmentSubmission)
