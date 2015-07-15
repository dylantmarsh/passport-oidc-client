var rp = require("request-promise");

exports = module.exports = {
    /**
     * @name _promiseFactory
     * @type DefaultPromiseFactory
     */

    /**
     * @param {XMLHttpRequest} xhr
     * @param {object.<string, string>} headers
     */
    setHeaders: function (xhr, headers) {
        var keys = Object.keys(headers);

        for (var i = 0; i < keys.length; i++) {
            var key = keys[i];
            var value = headers[key];

            xhr.setRequestHeader(key, value);
        }
    },

    /**
     * @param {string} url
     * @param {{ headers: object.<string, string> }} [config]
     * @returns {Promise}
     */
    getJSON : function (url, config) {
        
        // set headers in advanced scenario
        var options = {
            uri: url,
            strictSSL: false,
            json: true,
            //proxy: 'http://localhost:8888'
        };
        
        return rp(options).then(function(jsonObject){
            return jsonObject;
        }, function(error){
            return error;
        }).catch(console.error);
    }
};