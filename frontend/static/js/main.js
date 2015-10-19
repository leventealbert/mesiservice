function UsersCtrl($scope, $http, $filter) {
    'use strict';

    $scope.users = [];
    $scope.errors = [];

    $http.get('/api/users').then(function(res) {
        if (res.data.error) {
            $scope.log(res.data.error)
        } else {
            $scope.users = res.data;
        }
    }, function(msg) {
        $scope.log(msg.data);
    });

    $scope.log = function(msg) {
        $scope.errors.push(msg);
    };
}