function merge_sort(array, comparison) {
    if (array.length < 2) {
        return array;
    }

    var middle = Math.ceil(array.length / 2);

    return merge(
        merge_sort(array.slice(0, middle), comparison),
		merge_sort(array.slice(middle), comparison),
		comparison
    );
}

function merge(left, right, comparison) {
    var result = new Array();

    while ((left.length > 0) && (right.length > 0)) {
        if (comparison(left[0], right[0]) <= 0) {
            result.push(left.shift());
        } else {
            result.push(right.shift());
        }
    }

    while (left.length > 0) {
        result.push(left.shift());
    }

    while (right.length > 0) {
        result.push(right.shift());
    }
    
    return result;
}

function reorder(tbodyid, column,filter) {
    if (filter == null) {
        filter = function(v) { return v; }
    }

    var order = 1;
    var tbody = $("#" + tbodyid);
    var rows = $("#" + tbodyid + " tr").get();

    if (tbodyid == sorttbodyid && column == sortcolumn) {
        order = -sortorder;
    }

    sortorder = order;
    sortcolumn = column;

    var rowsort = new Array();
    $.each(rows, function (i, row) {
        rowsort.push({ key: filter($(row).children().eq(column).text().toUpperCase()), row: row });
    });

    rowsort = merge_sort(rowsort, function (rowa, rowb) {
        var a = rowa.key;
        var b = rowb.key;
        return (a < b) ? -order : (a > b) ? order : 0;
    });

    $.each(rowsort, function (i, row) {
        tbody.append(row.row);
    });
}

var sorttbodyid = "";
var sortorder = 0;
var sortcolumn = -1;
