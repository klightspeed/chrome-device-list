var columnfilters = [];
var updatefields = [];
var columnfields = [];

var devices = [];
var linkkey = null;

function parsedate(v) {
  return Date.parse(v)||0;
}

function updateworker() {
  $("#loading").show();
  $.ajax({
    url: "devlist?id=" + linkkey,
    success: update_devices,
    complete: function () {
      setTimeout("updateworker()", 300000);
    }
  });
}

function update_device(i, device, domainname) {
  if (device['deviceId'] in devices) {
    var dev = devices[device['deviceId']];

    $.each(updatefields, function (i, field) {
      var cell = dev[field];
      var value = device[field];
      if (cell.text() != value) {
        cell.text(value);
        if (field == "status") {
          cell.removeClass();
          if (value == "ACTIVE") {
            cell.addClass("status_active");
          } else {
            cell.addClass("status_inactive");
          }
        } else if (field == "annotatedUser" || field == "userActive") {
          cell.removeClass();
          if (device['annotatedUser'] != "") {
            if (device['userActive'] == "Yes") {
              cell.addClass("status_active");
            } else {
              cell.addClass("status_inactive");
            }
          }
        } else if (field == "recentUsers") {
          cell.removeClass();
          if (device['recentUsers'] != "") {
            if (device['recentUserActive'] == "Yes") {
              cell.addClass("status_active");
            } else {
              cell.addClass("status_inactive");
            }
          }
        }
      }
    });
  } else {
    var dev = [];
    dev['serialLink'] = $("<td></td>").addClass("ident")
                                      .append($("<a></a>")
                                        .attr("target", "_blank")
                                        .attr("href", "https://admin.google.com/" + domainname + "/AdminHome?fral=1#DeviceDetails:deviceType=CHROME&deviceId=" + device['deviceId'])
                                        .text(device['serialNumber']));

    $.each(device, function(key, value) {
      var cell = $("<td></td>").text(value);
      if (key == "serialNumber" || key == "macAddress") {
        cell.addClass("ident");
      } else if (key == "status") {
        cell.removeClass();
        if (value == "ACTIVE") {
          cell.addClass("status_active");
        } else {
          cell.addClass("status_inactive");
        }
      } else if (key == "annotatedUser" || key == "userActive") {
        cell.removeClass();
        if (device['annotatedUser'] != "") {
          if (device['userActive'] == "Yes") {
            cell.addClass("status_active");
          } else {
            cell.addClass("status_inactive");
          }
        }
      } else if (key == "recentUsers") {
        cell.removeClass();
        if (device['recentUsers'] != "") {
          if (device['recentUserActive'] == "Yes") {
            cell.addClass("status_active");
          } else {
            cell.addClass("status_inactive");
          }
        }
      }
      dev[key] = cell;
    });

    devices[device['deviceId']] = dev;

    var devrow = $("<tr></tr>");

    $.each(columnfields, function(i, colname) {
      devrow.append(dev[colname]);
    });
    
    $("#devices_tbody").append(devrow);
  }
}

function update_devices(data) {
  var devlist = data['devices'];
  var domainname = data['domainname'];
  if (devlist != null) {
    $.each(devlist, function(i, dev){ update_device(i, dev, domainname); });
    reorder("devices_tbody", sortcolumn, columnfilters[sortcolumn], true);
    $("#lastupdate").text(data['updated']);
    $("#loading").hide();
  }
}

