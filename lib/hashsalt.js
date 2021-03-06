'use strict';

var crypto = require('crypto');
var Promise = require("bluebird");

var iterations = 10000;
var password = function(password) {
	return {
		hash: function(salt) {
			return new Promise(function(res, rej){
				var doHash = function(salt){
					crypto.pbkdf2(password, salt, iterations, 64, 'sha1', function(err, key) {
						if(err){
							rej(err);
							return;
						}
						var result = 'pbkdf2$' + iterations + 
									'$' + key.toString('hex') + 
									'$' + salt.toString('hex');
						res(result);
					})
				}

				if(!password) {
					rej(new Error('No password provided'));
					return;
				}
				if(typeof salt === 'undefined'){
					crypto.randomBytes(64, function(err, gensalt) {
						if(err){
							rej(err);
							return;
						}
						doHash(gensalt);
					});
				}
				else
					doHash(new Buffer(salt, 'hex'));
			})
		},

		verifyAgainst: function(hashedPassword) {
			var me = this;
			return new Promise(function(res, rej){
				if(!hashedPassword || !password){
					res(false);
					return;
				}

				var key = hashedPassword.split('$');
				if(key.length !== 4 || !key[2] || !key[3]){
					rej(new Error('Hash not formatted correctly'));
					return;
				}
				if(key[0] !== 'pbkdf2' || key[1] !== iterations.toString()){
					rej(new Error('Wrong algorithm and/or iterations'));
					return;
				}
				me.hash(key[3])
				.then(newHash => {
					res(newHash === hashedPassword)
				})
				.catch(error => {
					rej(error);
				})
			})
		}
	};
}

module.exports = password;
