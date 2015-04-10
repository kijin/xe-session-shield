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
	
	// Get the CSRF token.
	var token = $("meta[name='XE-Shield-CSRFToken']").attr("content");
	
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
	
	// Add the token to every AJAX call, In case third-party code calls $.ajax() directly.
	$.ajaxPrefilter(function(options) {
		if(!options.url || options.url.indexOf(window.default_url) !== 0) return;
		if(!options.headers) options.headers = {};
		options.headers["X-Shield-CSRFToken"] = token;
	});
	
	// Add the token to every POST form on the web page.
	$(function() {
		$.fn.xe_shield_add_hidden_input = function() {
			return $(this).each(function() {
				if($(this).data("csrftoken-checked") === "Y") return;
				if($(this).attr("action") && $(this).attr("action").match(/^(https?:)?\/\//i) && $(this).attr("action").indexOf(window.default_url) !== 0) {
					return $(this).data("csrftoken-checked", "Y");
				}
				$("<input />").attr({ type: "hidden", name: "xe_shield_csrftoken", value: token }).appendTo($(this));
				return $(this).data("csrftoken-checked", "Y");
			});
		};
		$("form[method='post']").xe_shield_add_hidden_input();
		$(document).on("submit", "form[method='post']", $.fn.xe_shield_add_hidden_input);
		$(document).on("focus", "input", function() {
			$("form[method='post']").xe_shield_add_hidden_input();
		});
		
	});
	
})(jQuery);
