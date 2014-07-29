var columnfilters = [];
var updatefields = [];
var columnfields = [];

var devices = [];
var linkkey = null;

function parsedate(v) {
  return Date.parse(v)||0;
}

function updateworker() {
  $("#lastupdate").text("Loading");
  $.ajax({
    url: "devlist?id=" + linkkey,
    success: update_devices,
    complete: function () {
      setTimeout("updateworker()", 60000);
    }
  });
}

function update_device(i, device) {
  if (device['deviceId'] in devices) {
    var dev = devices[device['deviceId']];

    $.each(updatefields, function (i, field) {
      var cell = dev[field];
      if (cell.text() != device[field]) {
        cell.text(device[field]);
      }
    });
  } else {
    var dev = [];
    dev['serialLink'] = $("<td></td>").addClass("ident")
                                      .append($("<a></a>")
                                        .attr("href", "https://admin.google.com/AdminHome?fral=1#DeviceDetails:deviceType=CHROME&deviceId=" + device['deviceId'])
                                        .text(device['serialNumber']));

    $.each(device, function(key, value) {
      var cell = $("<td></td>").text(value);
      if (key == "serialNumber" || key == "macAddress") {
        cell.addClass("ident");
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
  if (devlist != null) {
    $.each(devlist, update_device);
    reorder("devices_tbody", sortcolumn, columnfilters[sortcolumn], true);
    $("#lastupdate").text(data['updated']);
  }
}

