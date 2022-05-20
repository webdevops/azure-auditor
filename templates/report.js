{{ $root := . }}
// ################################
// Global settings
// ################################

let globalSettingsKey = "auditor-global-settings";
let globalSettings = {};

// restore settings
try {
    globalSettings = JSON.parse(localStorage.getItem(globalSettingsKey));
    if (globalSettings && typeof globalSettings === 'object') {
        let settingInputList = $(".settings input:checkbox")
        $.each(globalSettings, (settingName, settingValue) => {
            $(".global-settings input:checkbox").each((idx, element) => {
                let el = $(element);
                if (el.data("setting-name") === settingName) {
                    el.attr("checked", settingValue);
                }
            });
        })
    } else {
        globalSettings = {};
    }
} catch (e) {
    globalSettings = {};
}

let processGlobalSettings = () => {
    $(".global-settings input:checkbox").each((idx, element) => {
        let el = $(element);
        let settingName = el.data("setting-name");
        if (el.is(':checked')) {
            globalSettings[settingName] = true;
            $("body").addClass(settingName);
        } else {
            globalSettings[settingName] = false;
            $("body").removeClass(settingName);
        }
    });

    try {
        localStorage.setItem(globalSettingsKey, JSON.stringify(globalSettings));
    } catch(e) {}
};

$(document).on("change", ".global-settings input:checkbox", processGlobalSettings);
processGlobalSettings();

// ################################
// Report
// ################################

let reportName = "{{ $root.RequestReport }}";
let reportAjaxUrl = "{{ $root.ServerPathReport }}/data";
let reportAjaxParams = {report:reportName, groupBy: "Status"};

let reportFilter = [];

if (!reportName) {
    return;
}

let formSaveToHash = () => {
    let formData = {};
    $("#report-form :input").each((num, el) => {
        let formEl = $(el);
        let fieldName = formEl.attr("id");
        let fieldValue = formEl.val();
        fieldValue = fieldValue.trim();

        formData[fieldName] = fieldValue;
    });

    let hashString = btoa(JSON.stringify(formData));
    window.location.hash = hashString;
};

let loadFromHash = () => {
    try {
        if (window.location.hash && window.location.hash.length >= 2) {
            let hashString = window.location.hash.substring(1);
            let formData = jQuery.parseJSON(atob(hashString));

            $("#report-form :input").val("");
            Object.keys(formData).forEach((fieldName) => {
                $("#report-form #" + fieldName + ":input").val(formData[fieldName]);
            });
        }
    } catch(e) {}
};

const yamlLine = new RegExp('^([^:\n]+):([^\n]*)$', 'gim');
let yamlFormatter = (cell, formatterParams) => {
    let val = cell.getValue();
    try {
        val = val.replaceAll(yamlLine, "<b>$1:</b>$2");
    } catch (e) {}
    return val;
};

let ajaxRequestFunc = (url, config, params) => {
    url = url + "?" + new URLSearchParams(params).toString();
    return new Promise(function (resolve, reject) {
        fetch(url, config)
            .then(response => {
                let reportTime = response.headers.get("x-report-time");
                if (reportTime) {
                    $("#report-time span.time").text(reportTime);
                }
                return response.json();
            })
            .then(data => {
                resolve(data);
            })
            .catch((error) => {
                reject(error);
            });
    });
};

let table = new Tabulator("#report-table", {
    ajaxContentType: "json",
    ajaxRequestFunc: ajaxRequestFunc,

    columns: [
        {title:"Status", field:"status", formatter:"tickCross", width:115},
        {title:"Resource", field:"resource", formatter:yamlFormatter, formatterPrint:yamlFormatter},
        {title:"Rule", field:"rule", formatter:"plaintext",  width:300},
    ],

    groupBy: "groupBy",
    groupToggleElement: "header",

    placeholder: "no report data found",

    height: "800px",
    layout: "fitColumns",

    pagination: true,
    paginationSize: 10,
    paginationSizeSelector: [5, 10, 25, 50, 100, 250, true],

    printHeader: $("#report-title").html(),
    printRowRange: "active",
    printAsHtml: true,

    persistence: {
        sort: true,
        filter: true,
        group: false,
        page: true,
        columns: false,
    },
    persistenceMode: true,
});

let refreshTableData = () => {
    // reset ajax params
    reportAjaxParams = {report:reportName};

    // add filter params
    $("#report-form :input[data-report-param]").each((num, el) => {
        el = $(el);
        let paramName = el.data("report-param");
        let paramValue = el.val();
        if (paramValue !== "") {
            switch (paramName) {
                case "fields":
                    paramValue = paramValue.replaceAll("\n", ":");
                    break;
            }
            reportAjaxParams[paramName] = paramValue;
        }
    });

    table.setData(reportAjaxUrl, reportAjaxParams);
};

let refreshTableFilter = () => {
    reportFilter = [];
    $("#report-form :input[data-report-filter]").each((num, el) => {
        el = $(el);
        let fieldName = el.data("report-filter");
        let fieldValue = el.val();

        if (fieldValue !== "") {
            switch (fieldName) {
                case "resource":
                    fieldValue.split("\n").forEach(value => {
                        value = value.trim();
                        if (value !== "") {
                            reportFilter.push({field:fieldName, type:"like", value:value});
                        }
                    });
                    break;
                default:
                    reportFilter.push({field:fieldName, type:"like", value:el.val()});
                    break;
            }
        }
    });
    table.setFilter(reportFilter);
};

table.on("tableBuilt", () => {
    $(document).on("click", "#report-print", function() {
        table.print();
    });

    let resetTableFilterSettings = () => {
        $("#report-form :input").each((num, el) => {
            let formEl = $(el);
            formEl.val(formEl.data("default"));
        });
    };

    $(document).on("click", "#report-reload", () => {refreshTableData()});
    $(document).on("click", "#report-download-csv", () => {table.download("csv", "report.csv")});
    $(document).on("click", "#report-download-json", () => {table.download("json", "report.json")});
    $(document).on("click", "#report-reset", () => {
        table.blockRedraw();
        resetTableFilterSettings();
        window.location.hash = "";
        refreshTableData();
        refreshTableFilter();
        table.restoreRedraw();
    });
    $(document).on("click", "#report-group-collapse", () => {
        table.blockRedraw();
        table.getGroups().forEach((el,i) => {el.hide()});
        table.restoreRedraw();
    });
    $(document).on("click", "#report-group-expand", () => {
        table.blockRedraw();
        table.getGroups().forEach((el,i) => {el.show()});
        table.restoreRedraw();

    });

    window.foo = table;


    $(document).on("click", ".nav-link", function(e) {
        let el = $(this);
        let url = el.attr("href");

        if (globalSettings["save-filter-settings"]) {
            formSaveToHash();
            url += window.location.hash;
        }

        window.location.assign(url);
        return false;
    });

    $(document).on("change", "#report-form :input", function(event) {
        let el = $(this);

        formSaveToHash();

        table.blockRedraw();
        if (el.data("report-refresh")) {
            refreshTableData();
        }
        refreshTableFilter();
        table.restoreRedraw();
    });

    table.blockRedraw();
    resetTableFilterSettings();
    loadFromHash();
    refreshTableData();
    refreshTableFilter();
    table.restoreRedraw();
});
