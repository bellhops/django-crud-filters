from rest_framework import serializers


# Swagger requires us to have serializers for all modelViewSets, even when the
# underlying model is an abstract class and doesn't really need a serializer.
# This serializer can be used for those abstract classes.
class AbstractModelSerializer(serializers.Serializer):

    class Meta:
        model = None
