from django.urls import path
from .views import TokensProviderView, FetchTokenView,UserInfoView,RefreshTokenView

urlpatterns = [
    path('validatetoken/', TokensProviderView.as_view(), name='token_provider'),
    path('fetchtoken/', FetchTokenView.as_view(), name='fetch_token'),
    path('userinfo/', UserInfoView.as_view(), name='UserInfo'),
    path('refreshtoken/', RefreshTokenView.as_view(), name='refresh_token'),
]
