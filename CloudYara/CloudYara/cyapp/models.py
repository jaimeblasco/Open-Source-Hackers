from django.db import models
from taggit.managers import TaggableManager


CLASSIFICATION_CHOICES = (
    ('public', 'Public'),
    ('private', 'Private'),
)

# Create your models here.
class Rule(models.Model):
    name = models.CharField(max_length=200)
    rule = models.TextField()
    source = models.CharField(max_length=200)
    description = models.CharField(max_length=200)
    reported_by_user = models.ForeignKey(User, blank=True, null=True)
    classification = models.CharField(max_length=100, choices=CLASSIFICATION_CHOICES, blank=True, null=True)
    version = models.CharField(max_length=20)
    valid_rule = models.BooleanField()
