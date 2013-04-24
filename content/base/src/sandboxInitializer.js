/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;
const Cu = Components.utils;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");

function SandboxInitializer() { }

SandboxInitializer.prototype = {
  classID:          Components.ID("{3c41623d-0a4f-4c80-9173-17bb2ade241d}"),
  QueryInterface:   XPCOMUtils.generateQI([Ci.nsISandboxInitializer]),
  
  /**
   * Labels are expected to have the form:
   * [ [ "p1", "p2", ...] , [ "q1", "q2", ...], ...]
   */
  _parseLabel: function(win, jsonLabel) {
    var label = new win.Label();
    var formatErr = 
      'Label expected to be a JSON value: [ [ "p1", "p2", ...] , [ "q1", "q2", ...], ...]';
    var clauses = JSON.parse(jsonLabel);
    if (!Array.isArray(clauses)) { throw formatErr; }
    for (var i = 0; i < clauses.length; i++) {
      var disjs = clauses[i];
      if (!Array.isArray(disjs)) { throw formatErr; }
      label.and(new win.Role(disjs)); 
    }
    return label;
  },
  init : function(win, jsonLabel) {
    //win.console.log("Got JSON label: "+jsonLabel);

    try {
      var label = this._parseLabel(win, jsonLabel);
      if (win.Sandbox.enableSandboxed()) {
        label.and(win.Sandbox.getPrivacyLabel());
      }
      win.Sandbox.setPrivacyLabel(label);
      //win.console.log("Initialized sandbox-mode: "+label);
      return true;
    } catch(e) {
      //win.console.log("Failed to initialize Sandbox: "+e);
      return false;
    }
  }
};

var components = [SandboxInitializer];
this.NSGetFactory = XPCOMUtils.generateNSGetFactory([SandboxInitializer]);
