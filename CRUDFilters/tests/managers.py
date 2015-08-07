from django.db.models.query import QuerySet


class TestQuerySet(QuerySet):

    def field_one_true(self, queryset, user, request):
        return queryset.filter(field_one=True)

    def field_two_true(self, queryset, user, request):
        return queryset.filter(field_two=True)

    def field_three_true(self, queryset, user, request):
        return queryset.filter(field_three=True)

    def field_four_true(self, queryset, user, request):
        return queryset.filter(field_four=True)

    def field_five_true(self, queryset, user, request):
        return queryset.filter(field_five=True)

    def no_objects(self, queryset, user, request):
        return queryset.none()


TestManager = TestQuerySet.as_manager()
