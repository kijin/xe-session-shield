/**
 * @file session_shield.csrftoken.js
 * @author Kijin Sung <kijin@kijinsung.com>
 * @license LGPL v2.1 <http://www.gnu.org/licenses/lgpl-2.1.html>
 * @brief Session Shield addon - CSRF token handling script
 * 
 * This script adds a CSRF token to every POST form on the web page,
 * and also injects the token into XE's various AJAX functions.
 */
(function($) {
	
	$(function() {
		
		// Get the token inserted into the document body by the Session Shield class.
		var token = $("#xe_shield_csrftoken").data("token");
		
		// Add the token to every POST form on the web page.
		$("form[method='post']").each(function() {
			$(this).append('<input type="hidden" name="xe_shield_csrftoken" value="' + token + '" />');
		});
		
		// Define a simple jQuery plugin with utility functions and backups of XE's AJAX functions.
		$.fn.xe_shield_backup = {
			arr2obj : function(arr) {
				var ret = {};
				for(var key in arr) {
					if(arr.hasOwnProperty(key)) ret[key] = arr[key];
				}
				return ret;
			},
			addtoken : function(data) {
				if(typeof data.xe_shield_csrftoken === "undefined") {
					data.xe_shield_csrftoken = token;
				}
				return data;
			},
			exec_html : $.fn.exec_html,
			exec_json : $.exec_json,
			exec_xml : $.exec_xml
		};
		
		// Overwrite XE's AJAX functions with wrappers to add the token to every request.
		$.exec_html = $.fn.exec_html = window.exec_html = function(action, data, type, func, args) {
			data = $.fn.xe_shield_backup.addtoken(data ? data : {});
			$.fn.xe_shield_backup.exec_html(action, data, type, func, args);
		};
		$.exec_json = $.fn.exec_json = window.exec_json = function(action, data, callback_sucess, callback_error) {
			data = $.fn.xe_shield_backup.addtoken(data ? data : {});
			$.fn.xe_shield_backup.exec_json(action, data, callback_sucess, callback_error);
		};
		$.exec_xml = $.fn.exec_xml = window.exec_xml = function(module, act, params, callback_func, response_tags, callback_func_arg, fo_obj) {
			if($.isArray(params)) params = $.fn.xe_shield_backup.arr2obj(params ? params : {});
			params = $.fn.xe_shield_backup.addtoken(params ? params : {});
			$.fn.xe_shield_backup.exec_xml(module, act, params, callback_func, response_tags, callback_func_arg, fo_obj);
		};
		
	});
	
})(jQuery);
