'use strict';

angular.module('myApp.view1', ['ngRoute'])

.config(['$routeProvider', function($routeProvider) {
  $routeProvider.when('/view1', {
    templateUrl: 'view1/view1.html',
    controller: 'View1Ctrl'
  });
}])

.controller('View1Ctrl', ['$scope','$http',function($scope, $http) {
  $scope.plaintext = 'hello';
  $scope.encrypt = function() {
    $http.get('/app/public.pem').then(
        function(response) {
          var crypt = new JSEncrypt();
          crypt.setKey(response.data);

          var encPw = crypt.encrypt($scope.plaintext);
          $http.post('http://localhost:8080/api/auth/', { username: 'sepp', password: encPw });
        }
      );
  }
}]);