/**
 * @file session_shield.csrftoken.js
 * @author Kijin Sung <kijin@kijinsung.com>
 * @license LGPL v2.1 <http://www.gnu.org/licenses/lgpl-2.1.html>
 * @brief Session Shield addon - CSRF token handling script
 */
(function($) {
	
	$(function() {
		
		$.fn.xe_shield_backup = {
			arr2obj : function(arr) {
				var ret = {};
				for(var key in arr) {
					if(arr.hasOwnProperty(key)) ret[key] = arr[key];
				}
				return ret;
			},
			exec_html : $.fn.exec_html,
			exec_json : $.exec_json,
			exec_xml : $.exec_xml
		};
		
		$.exec_html = $.fn.exec_html = window.exec_html = function(action, data, type, func, args) {
			if(typeof data === 'undefined') data = {};
			if(typeof data.xe_shield_csrftoken === "undefined") {
				data.xe_shield_csrftoken = $("#xe_shield_csrftoken").data("token");
			}
			$.fn.xe_shield_backup.exec_html(action, data, type, func, args);
		};
		
		$.exec_json = $.fn.exec_json = window.exec_json = function(action, data, callback_sucess, callback_error) {
			if(typeof data === 'undefined') data = {};
			if(typeof data.xe_shield_csrftoken === "undefined") {
				data.xe_shield_csrftoken = $("#xe_shield_csrftoken").data("token");
			}
			$.fn.xe_shield_backup.exec_json(action, data, callback_sucess, callback_error);
		};
		
		$.exec_xml = $.fn.exec_xml = window.exec_xml = function(module, act, params, callback_func, response_tags, callback_func_arg, fo_obj) {
			if(!params) params = {};
			if($.isArray(params)) params = $.fn.xe_shield_backup.arr2obj(params);
			if(typeof params.xe_shield_csrftoken === "undefined") {
				params.xe_shield_csrftoken = $("#xe_shield_csrftoken").data("token");
			}
			$.fn.xe_shield_backup.exec_xml(module, act, params, callback_func, response_tags, callback_func_arg, fo_obj);
		};
		
		var token = $("#xe_shield_csrftoken").data("token");
		if ((typeof token === "string" || token instanceof String) && token.length > 0) {
			$('form[method="post"],form[method="POST"]').each(function() {
				$(this).append('<input type="hidden" name="xe_shield_csrftoken" value="' + token + '" />');
			});
		}
		
	});
	
})(jQuery);
