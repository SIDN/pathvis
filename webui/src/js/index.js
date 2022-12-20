import { DataSet } from 'vis-data';
import { Network } from 'vis-network';
import $ from 'jquery';
import { DateTime } from 'luxon';
import bootstrap from 'bootstrap/dist/js/bootstrap.js';
//import 'bootstrap/dist/css/bootstrap.css';
//import 'style.css;

// Global variables (datastore)
var networkviz = null;
var tracedb = null;
var socket = null; // websocket that connects
var tracehistory = []; // Array with historic traceroute objects

const max_tracehistory= 1000; //maximum amount of history messages
const max_messages = 5; //maximum amount of network messages

const color_primary = '#362ec4'; // 2stic dark purple
const color_secondary = '#9366bd'; // 2stic purple
const color_tenary = '#24b3b2'; // sidnlabs cyan
const color_success = '#178d30'; // sidn green
const color_danger = '#e85422'; // sidn red-orange
const color_light = '#ede'; // not entirely white
const color_dark = '#333';  // not entirely black
//var color_default = '#D2E5FF'; // default visjs node color
const color_default = '#D2E5FF'; // default visjs node color
const color_end = '#ff9900'; // original destination color
const color_you = '#ffffcc'; // original start color

const color_node_text = color_dark;
const color_home = color_you;
const color_destination = color_end;
const color_intermediate = color_default;
const color_old = color_danger;
const color_new = color_success;

// User can select specific destinations to show (the rest are hidden)
var filterDestinations = [];
var notifyChanges = [];
var usedPorts = new Set();

// If true, draw one node per ASN, instead of per IP. Internal datastructure remains the same
var ASNView = false;
// We can cluster by ASN if the user so desires. vis.js has clustering options but you need to create a separate cluster
// data structure for all of them
var ASNClusters = {};

function init() {
    tracedb = new TraceDB(this);
    networkviz = new NetworkViz(this, tracedb);
    let container = document.getElementById('network-currentstate');
    networkviz.draw(container);
}

// If filterDestinations (a list of destinations where only those traces should be shown) is set,
// this function checks whether a node should be shown, which is when:
// - filterDestinations is empty (nothing set), OR
// - node.destinations is empty (the 'you' node), OR
// - the node has a destination which is also in the filterDestinations array
function showFilteredNode(node) {
    return filterDestinations.length === 0 ||
           node.destinations.length === 0 ||
           filterDestinations.filter(function (e) { return node.destinations.indexOf(e) >= 0}).length > 0;
}

function addASNCluster(network, asn) {
    if (asn == "NA" || asn == '*' || asn == null) {
        return null;
    }
    let clusterId = "cluster-" + asn;
    if (ASNClusters[clusterId]) {
        return ASNClusters[clusterId];
    } else {
        let clusterOptionsByData = {
            joinCondition: function (childOptions) {
                if (childOptions.info) {
                    return childOptions.info.asn == asn && !childOptions.hidden;
                } else {
                    return false;
                }
            },
            clusterNodeProperties: {
                id: clusterId,
                shape: 'ellipse',
                shadow: true,
                borderwidth: 3,
                color: {background: color_intermediate},
                label: 'AS ' + asn,
                allowSingleNodeCluster: false, // Disable this to prevent making a cluster for an AS with only 1 node
            },
            processProperties: function (clusterOptions, childNodes, childEdges) {
                // update the label to show the number of nodes, and update the color if necessary
                // also hide the cluster itself if all children are hidden
                let hidden = true;
                for (let i=0; i < childNodes.length; i++) {
                    let child = childNodes[i]
                    for (let j=0; j<child.destinations.length; j++) {
                        if (child.ip == child.destinations[j]) {
                            clusterOptions.color = { background: color_destination}
                        }
                        if (!child.hidden) {
                            hidden = false;
                        }
                    }
                }
                clusterOptions.label = clusterOptions.label + "\n" + childNodes.length + " nodes";
                if (hidden) {
                    clusterOptions.hidden = true;
                } else {
                    clusterOptions.hidden = false;
                }
                return clusterOptions;
            }
        }
        ASNClusters[clusterId] = clusterOptionsByData;
        network.cluster(clusterOptionsByData);
        // loop through the edges to see whether we haven't messed up the layout too much
        console.log("Added new cluster, checking edges");
        network.getClusteredEdges().forEach((e) => {
            console.log(e);
        });
        return clusterOptionsByData;
    }
}

class TraceDB {
    // Database for active traces destination ip is public key
    traceroutes = {};
    expire = null;

    constructor(ctx, expire_after=null) {
        this.expire = expire_after;
    }

    listTraces() {
        return traceroutes.keys();
    }

    addTrace(destination, traces) {
        this.traceroutes[destination] = traces;
    }

    getTrace(destination) {
        if (destination in this.traceroutes) {
            return this.traceroutes[destination];
        }
        return [];
    }

    deleteTrace(destination) {
        if (destination in this.traceroutes) {
            delete this.traceroutes[destination];
        }
    }

    seen(destination){
        return (destination in this.traceroutes);
    }

    clear() {
        this.traceroutes={};
    }

    indexOf(destination) {
        alert("this is from the old implementation")
    }

};

class NetworkViz {
    nodes = new DataSet([]);
    edges = new DataSet([]);
    tracedb = null;

    constructor(ctx, tracedb) {
        // First one-time initialisation of the webapp
        this.tracedb = tracedb
        this.options = {
            autoResize:true,
            layout: {
                hierarchical: {
                    levelSeparation: 100,
                    direction: 'UD',
                    shakeTowards: 'roots',
                    sortMethod: 'directed',
                    nodeSpacing: 200,
                    //edgeMinimization: true,
                    //blockShifting: true,
                    //parentCentralization: true
                },
                improvedLayout: true,
            },
            "physics": {
                'enabled': false,
                'hierarchicalRepulsion': {
                    avoidOverlap:  1,
                    //springLength: 80,
                    springConstant: 5,
                    damping: 1,
                },
            },
            nodes: { font: { size: 14, color: color_node_text }, shape: 'box', shadow: true }
        };

        this.clear();

    };

    getNodeId(ip, hopnr = null) {
        // returns Datanode id, or null if not found
        let grouped = this.nodes.get({
            filter: (item) => {return (ip == item['ip']) || (ip == null && item['hopnr'] == hopnr)}
        });
        if (grouped.length > 0) {
            return grouped[0].id;
        }
        return null;
    };

    addToCurrentState(destination, traceroute) {
        // Adds traceroute to current state graph
        // For each found hop, see if it exists already
        //  (match by hostname). For *-hosts, we match by hopnr
        //  but only as long as the *'s are in the beginning of
        //  the traceroute, since they are most likely the same.
        let firstNonStar = false;
        let previd = 0;
        let full_path_roa = traceroute.filter(hop => hop.asn != "private_ip").every(hop => hop.roa === 'valid')

        // Loop through each part of the traceroute to add
        traceroute.forEach((elem, elemidx) => {
            // keep count to check for non-* nodes, mark as such
            if (!firstNonStar && elem.ip != null) {
                firstNonStar = true;
            }
            let id = this.getNodeId(elem.ip, elem.hopnr);
            if (elem.ip == null) {
                if (firstNonStar) {
                    id = null; // unknown, make it a new host
                } else if (previd != 0) {
                    // check the previous node; if it has a next hop that also has no information towards the current destination, skip adding a new node
                    this.edges.forEach((e) => {
                        if (e.from == previd && e.destinations.indexOf(destination) >= 0) {
                            let prevNextNode = this.nodes.get(e.to);
                            if (prevNextNode.ip == null) {
                                id = e.to;
                            }
                            //return;
                        }
                    });
                }
            }
            // if id=null, we need to add a new node.
            // otherwise, we merge.
            if (id == null) {
                // id will be the next available identifier
                id = this.nodes.getIds().reduce(function(a, b) {
                    return Math.max(a, b);
                }, -Infinity) + 1;
                let label = createNodeLabel(elem);

                let node = {id: id, label: label, ip: elem.ip, destinations: [destination], hopnr: elem.hopnr, info: elem, color: {background: color_intermediate}}
                let cnode = null;
                // Only add the node if it isn't on the currently viewed path ('current path(s) only')
                node.hidden = !showFilteredNode(node);
                this.nodes.add([node]);
                if (ASNView) {
                    let clusterData = addASNCluster(this.visNetwork, node.info.asn);
                    if (clusterData) {
                        // trick to 'seamlessly' add a node to an existing cluster:
                        // expand it, then perform the clustering again
                        let cnode = this.visNetwork.body.nodes['cluster-' + node.info.asn];
                        if (cnode) {
                            this.visNetwork.openCluster(cnode.id);
                            this.visNetwork.cluster(clusterData);
                        }
                    }
                }

                // Now, update reference in traces with datanode identifier
                // This is used later on to establish which nodes are still active
                traceroute[elemidx].datanode = id;

                if (destination == elem.ip) {
                    // if this node is the final one, different color:
                    let background = color_destination;
                    if (full_path_roa) {
                        background = "#00ff00";
                    }
                    this.nodes.updateOnly({id: id, label: createNodeLabel(elem, true), destinations: [destination], dports: elem.dports, color: { background: background }});
                }
                // if orig, merge from 'home'
                if (previd != id) {
                    this.edges.add([{from: previd, destinations: [destination], to: id}]);
                }
                previd = id;
            } else {
                // update datanode identifier to the existing node
                traceroute[elemidx].datanode = id;

                // add the destination to the existing node
                let node = this.nodes.get(id).destinations.push(destination);

                // merge existing nodes, and check if they need a new edge
                let exists = this.edges.get({
                    filter: function (item) {
                        return item.from == previd && item.to == id;
                    }
                });
                exists.forEach(edge => {
                    if (!!edge.destinations.indexOf(destination)) {
                        edge.destinations.push(destination);
                    }
                });
                if (exists.length == 0) {
                    this.edges.add([{from: previd, destinations: [destination], to: id}]);
                }

                previd = id;
            }
        });
        // and finally, add to current state variable
        this.tracedb.addTrace(destination, traceroute);

        // update visualisation
        this.redraw();
    };

    removeInactiveNodes(destination, oldTrace, newTrace) {
        // Remove destination from all existing nodes
        this.nodes.get({ filter: node => node.destinations.includes(destination)})
            .forEach(node => {
                node.destinations = node.destinations.filter(dst => dst != destination);
                if (node.destinations.length == 0) {
                    this.nodes.remove(node)
                }
            });

        // Do the  same for edges
        this.edges.get({ filter: edge => edge.destinations.includes(destination)})
            .forEach(edge => {
                edge.destinations = edge.destinations.filter(dst => dst != destination);
                if (edge.destinations.length == 0) {
                    this.edges.remove(edge)
                }
            });

        this.redraw();
    };

    updateFilterDestinations() {
        let node_updates = [];
        this.nodes.forEach((node) => {
            node_updates.push({id: node.id, 'hidden': !showFilteredNode(node)});
        })
        this.nodes.update(node_updates);
        this.redraw();
    }

    setASNMode() {
        if (ASNView) {
            //this.visNetwork.setData(this.nodes);
            ASNClusters = {};
            this.nodes.forEach((node) => {
                if (node.info) {
                    addASNCluster(this.visNetwork, node.info.asn);
                }
            });
            this.redraw();
            //this.visNetwork.clustering.clusterByConnection();
        } else {
            //this.visNetwork.setData(this.nodes);
            for (let index of this.visNetwork.body.nodeIndices) {
                if (this.visNetwork.isCluster(index)) {
                    this.visNetwork.openCluster(index);
                }
            }
            ASNClusters = {};
            this.redraw();
        }
    }

    draw(container) {
        var data = {
            nodes: this.nodes,
            edges: this.edges
        };
        // initialize your network!
        this.visNetwork = new Network(container, data, this.options);
        //visNetwork.once('afterDrawing', () => { container.style.height = '70vh' });

        this.visNetwork.on('deselectNode', () => {
            $('#show-current-destinations-only').attr('disabled', true);
            $('#set-notification-destinations').attr('disabled', true);
        })

        this.visNetwork.on( 'click', (properties) => {
            let ids = properties.nodes;
            let eids = properties.edges;
            let clickedEdges = this.edges.get(eids);
            let clickedNodes = this.nodes.get(ids);
            let curEdge = clickedEdges[0];
            let curNode = clickedNodes[0];
            if (curNode && curNode.info) {
                updateInfo(curNode.info, "Node Info", ["datanode", "hopnr"]);
                $('#show-current-destinations-only').removeAttr('disabled');
                $('#set-notification-destinations').removeAttr('disabled');
            } else if (curEdge && curEdge.destinations) {
                const info = {};
                curEdge.destinations.forEach((value, idx) => info[`Destination ${idx+1}`] = value);
                updateInfo(info, "Edge Info", []);
            } else {
                ids.forEach((nodeId) => {
                    if (this.visNetwork.isCluster(nodeId)) {
                        this.visNetwork.openCluster(nodeId);
                        delete ASNClusters[nodeId];
                        //this.redraw();
                    }
                })

            }

        });


    };

    clear() {
        console.log('clearing graph')
        this.tracedb.clear()
        this.nodes.clear()
        this.edges.clear()
        this.nodes.add([{id: 0, label: 'You', hopnr: -1, destinations: [], ip: '127.0.0.1', color: { background: color_home}}]);
        this.redraw()
    }

    redraw() {
        if (!this.visNetwork) return this.edges;
        if (ASNView) {
            this.visNetwork.stabilize(10000);
        }
        this.visNetwork.fit();
    };

    fullRedraw() {
        this.visNetwork.destroy();
        let container = document.getElementById('network-currentstate');
        this.draw(container);
        this.setASNMode();
        this.visNetwork.fit();
    }
};

function createNodeLabel(hop, endpoint=false) {
    function describeHop(hop) {
        let who = "";
        // Ideally who has a link to the identifier that the user used to
        // set up the connection
        if (hop.cnames.length > 0) {
            who = hop.cnames[0] + '\n\n';
        }
        // First we try the domain name (from reverse lookup)
        if (who == "" && isNaN(hop.domain.slice(-1) && hop.domain.slice(-1) != ":")) { //if not an ip (ends with number)
            who = hop.domain + '\n\n';
        }
        if (who == ""){
            // Then the first part of ASN description
            if (hop.description) {
               who = hop.description.split(",")[0] + "\n\n";
            }
        }
        return who
    }

    let roamark = ""
    if (hop.roa == "valid") {
        roamark += "✅";
    }
    let label = roamark + 'AS:' + hop.asn + '\n\n' + hop.ip;
    if (hop.ip == null) {
        label = '???';
    }
    if (endpoint) {
        const who = describeHop(hop);
        label = roamark + 'AS:' + hop.asn + '\n\n' + who + hop.ip;
    }
    return label;
}

function displayNameForKey(key) {
    switch (key) {
        case "asn":
            return "ASN";
        case "cidr":
            return "CIDR";
        case "cnames":
            return "CNAMEs";
        case "country":
            return "Country";
        case "description":
            return "Description";
        case "dis":
            return "DIS";
        case "domain":
            return "Domain";
        case "dports":
            return "Destination ports";
        case "hostname":
            return "Hostname";
        case "ip":
            return "IP address";
        case "roa":
            return "ROA";
    }
    return key;
}

//Updates Node/Edge info sidebar
function updateInfo(info, title='Node info', filter_keys=[]) {
    let titleElement = document.getElementById('nodeinfo-title');
    titleElement.innerHTML=title;
    let list = document.getElementById('nodeinfo-list');
    let template = document.getElementById("nodeinfo-item-template");
    list.innerHTML = ''; // clear list
    //list.appendChild(template); //append template for next time
    for (const [key, value] of Object.entries(info)) {
        if (filter_keys.includes(key)) {
            continue; //filter item
        }
        let item = template.cloneNode(true); // cloned copy, including subelements
        let nk = item.getElementsByClassName('nodeinfo-key');
        let i=0; //we assume there is only one element ;)
        nk[i].innerHTML = displayNameForKey(key);
        let nv = item.getElementsByClassName('nodeinfo-value');
        nv[i].innerHTML = value;
        item.classList.remove('id'); //remove id (should be unique)
        item.classList.remove('d-none'); //make visible
        list.appendChild(item, list.firstChild);
    }

};

//Writes to Raw network messages log
function writelog(message) {
    // Arrange debugging of change:
    var div = document.getElementById('messages');
    if (div.childElementCount >= max_messages) {
        div.lastElementChild.remove();
    }
    //div.innerHTML += JSON.stringify(message) + '<br/>';
    var debugmsg = `<div class ="message"><span class="m_host">${message.destination}</span> `
    if (message.trace.length == 0) {
        debugmsg += '<span class="m_removed">expired</span>';
    }else if (message.change && (message.new === false)) {
        debugmsg += `<span class="m_change">changed</span> `;
    }else if (message.change && (message.new === true)){
        debugmsg += `<span class="m_new">new</span> `;
    }
    if (message.trace.length > 0) {
        message.trace.forEach(v => {
            debugmsg += '<span class="m_hop">' + v[0];
            debugmsg += ': ';
            debugmsg += v[1].ip ?? '*';
            debugmsg += '</span>, ';
        });
        debugmsg = debugmsg.slice(0, -2);
    }

    div.innerHTML = debugmsg +  '</div>' + div.innerHTML;
    div.scrollTop = 0;
}

function updatePortFilterList() {
    let knownports = {80: 'http', 443: 'https', 993: 'imaps'}
    let filter_list = document.getElementById('filter-destination-by-port');
    const existing = Array.from(filter_list.options).map((opt) => opt.value);
    //console.log(filter_list.options)
    usedPorts.forEach(port => {
        let portname = knownports[port];
        let friendlyname = `${port}`
        if (portname) {
            friendlyname = `${portname} (${port})`
        }
        if (!existing.includes(port.toString())) {
            filter_list.add(new Option(friendlyname, port));
        }
    });
}

function processMessage(message) {
    // Obtains message from the websocket with a new or changed traceroute.
    // Process into current state and store for history.
    let destination = message.destination;
    let seen = tracedb.seen(destination); //If we have a result then update
    let remove = !message.trace.length; // if array is empty remove = true

    networkviz.visNetwork.stopSimulation();

    if (message.change || !seen) {
        //console.log(message);
        writelog(message); //Write raw network message

        // Either way, first add the new traceroute to the graph:
        let traces = [];
        message.trace.forEach(function (v) {
            let hop = v[0];
            let tr = v[1];
            traces.push({hostname: tr.hostname, cnames: message.cnames, hopnr: hop,
                cidr: tr.cidr, country: tr.country, domain: tr.domain,
                asn: tr.asn, description: tr.description, ip: tr.ip, roa: tr.roa,
                datanode: -1, dports: message.dports, dis: tr.dis });
            message.dports.forEach(usedPorts.add, usedPorts);
        });

        updatePortFilterList();

        let oldtrace = tracedb.getTrace(destination);

        addToHistory(destination, oldtrace, traces);

        if (seen) {
            tracedb.deleteTrace(destination);
            networkviz.removeInactiveNodes(destination, oldtrace, traces);
            if (!remove) {
                networkviz.addToCurrentState(destination, traces);
            }else {
		console.log('expired', destination);
	    }
        } else {
            networkviz.addToCurrentState(destination, traces);
        }
    }
    networkviz.visNetwork.startSimulation();
}

function startConnection() {
    if (socket) { return };
    var socket = new WebSocket("ws://127.0.0.1:8765");

    socket.onmessage = function(event) {
        if (event.data == 'clear_cache') {
            console.log('received clear cache')
            networkviz.clear();
            return
        }
        var data = JSON.parse(event.data);
        processMessage(data);
    };

    socket.onopen = function(e) {
        console.log("backend connection established");
        let div = document.getElementById('statusmsg');
        div.innerHTML = 'Connected';
        div.setAttribute('class','badge bg-success');
    };

    socket.onclose = function(event) {
        let div = document.getElementById('statusmsg');
        div.innerHTML = 'Disconnected';
        div.setAttribute('class','badge bg-danger');

        if (event.wasClean) {
            console.log(`backend connection closed, code=${event.code} reason=${event.reason}`);
        } else {
            console.log('backend connection closed (unclean)');
        }
        // Retry in 5s
        setTimeout(startConnection, 5000);
    };

    socket.onerror = function(error) {
        let div = document.getElementById('statusmsg');
        div.innerHTML = 'Error';
        div.setAttribute('class','badge bg-danger');
        console.log(`Websocket raises an error: ${error.message}`);
        socket.close()
    };
}

function addToHistory(destination, oldtraces, newtraces) {
    // This function is called when a new traceroute needs to be added to the history
    // Update the history array


    // Limiting tracehistory causes array indexes to be reused
    // Clicking on an ui element often shows the new object instead of the old one
    //if (tracehistory.length >= max_tracehistory ) {
    //    tracehistory.shift();
    //}
    let idx = tracehistory.push({destination: destination, new: newtraces, old: oldtraces}) - 1;

    let oldTracesAvailable = false;
    let newTracesAvailable = false;
    if (Array.isArray(oldtraces) && oldtraces.length > 0) {
        oldTracesAvailable = true;
    }
    if (Array.isArray(newtraces) && newtraces.length > 0) {
        newTracesAvailable = true;
    }
    let change = false;

    if (oldTracesAvailable && newTracesAvailable && oldtraces.length === newtraces.length) {
        // we may not have changed, checking elements
        oldtraces.forEach((oldt, index) => {
            const newt = newtraces[index];
            if (oldt.ip != newt.ip) {
                change = true;
            }
        });
    }else{
        // Something must be different because lengths are unequal
        change = true;
    }

    if (!change) {
        // Nothing has actually changed visually so we dont add stuff
        return;
    }

    let set_old = new Set(oldtraces.map(t => t.ip));
    let set_new = new Set(newtraces.map(t => t.ip));
    let diff = new Set( [...set_new].filter( x => !set_old.has(x) ));
    let n_changes = [...diff].length;

    let time = DateTime.now();
    // Show in GUI
    let template = document.getElementById("history-item-template");
    let item = template.cloneNode(true); // cloned copy, including subelements
    // prepare cloned item with correct values
    item.removeAttribute("id");
    item.setAttribute('data-idx', idx);
    // Set the hostname and time
    let coll = item.getElementsByClassName('history-action');
    for (let i = 0; i < coll.length; i++) {
        let action = "meh";

        if (!oldTracesAvailable && newTracesAvailable) {
            action = "New path";
            coll[i].classList.add('text-success');
            item.onclick = 'return false;';
            item.classList.add('cursor-notallowed');
        }else if (oldTracesAvailable && newTracesAvailable) {
            action = `Path has ${n_changes} changes`;
            coll[i].classList.add('text-danger');
            if (notifyChanges.includes(destination)) {
                const n = new Notification(`Path to ${destination} changed`, { body: `${n_changes} changes detected on path to ${destination}`});
            }
        }else if (oldTracesAvailable && !newTracesAvailable) {
            action = "Path expired";
            coll[i].classList.add('text-info');
            item.onclick = 'return false;';
            item.classList.add('cursor-notallowed');
        }else if (!oldTracesAvailable && !newTracesAvailable) {
            action = "Path expired";
            coll[i].classList.add('text-info');
            item.onclick = 'return false;';
            item.classList.add('cursor-notallowed');
        }
        coll[i].innerHTML = action;
    }
    coll = item.getElementsByClassName('history-hostname');
    for (let i = 0; i < coll.length; i++) {
        coll[i].innerHTML = destination;
    }
    coll = item.getElementsByClassName('history-time');
    for (let i = 0; i < coll.length; i++) {
        coll[i].setAttribute("data-time", time);
        // Additionally, update the time automatically
        coll[i].setAttribute("data-updater", 
            setInterval(function () {
                let diff = DateTime.now().diff(time, ['hours', 'minutes', 'seconds']);
                if (diff.minutes == 0) {
                    if (diff.seconds > 1) {
                        if (coll[i].classList.contains('bg-warning')) {
                            coll[i].classList.add('bg-light');
                            coll[i].classList.add('text-dark');
                            coll[i].classList.remove('bg-warning');
                        }
                        coll[i].innerHTML = Math.floor(diff.seconds) + " seconds ago";
                    }
                } else {
                    if (diff.hours == 0) {
                        coll[i].innerHTML = diff.minutes + " minute(s) ago";
                    } else {
                        coll[i].innerHTML = diff.hours + " hour(s) ago";
                    }
                }
            }, 1000)
        );
    }

    // And set as visible:
    item.classList.remove('d-none');

    // Add item to the list, on top:
    let list = document.getElementById('history-list');
    list.insertBefore(item, list.firstChild);

    // Keep the amount of items below max_tracehistory
    if (list.childElementCount > max_tracehistory + 1){ //+1 one for template
        const template = list.lastElementChild //last element is a template
        // Don't forget to remove the interval
        coll = template.previousElementSibling.getElementsByClassName('history-time');
        for (let i=0; i<coll.length; i++) {
            clearInterval(coll[i].getAttribute("data-updater"));
        }
        template.previousElementSibling.remove(); //remove last entry
    }

}

function historyClick(elem) {
    let idx = elem.getAttribute("data-idx");
    // TODO: implement modal interface to show history change of element 'idx'
    // alert("Not implemented, but you clicked id=" + idx);
    let explorerelem = document.getElementById('history-explorer');
    var explorer = new bootstrap.Modal(explorerelem);
    let histitem = tracehistory[idx];

    document.getElementById("history-explorer-title").innerHTML = histitem.hostname;

    // Initialise history vis-network
    let dnodes = new DataSet([]);
    let dedges = new DataSet([]);
    let container = document.getElementById('network-history-state');

    var data = {
        nodes: dnodes,
        edges: dedges
    };

    var options = {
        autoResize:true,
        layout: {
            hierarchical: {
                levelSeparation: 100,
                direction: 'UD',
                shakeTowards: 'roots',
                sortMethod: 'directed',
                nodeSpacing: 200,
            },
            improvedLayout: true,
        },
        "physics": {
            'enabled': false,
            'hierarchicalRepulsion': {
                avoidOverlap:  1,
                //springLength: 80,
                springConstant: 5,
                damping: 1,
            },
        },
        nodes: { font: { size: 10, color: color_node_text }},
	edges: { smooth: { type: "continuous" }}
    };

    explorer.show();
    // initialize your network!
    let visNetwork = new Network(container, data, options);

    // Add home node
    dnodes.add([{id: 0, label: 'You',
        color: {
            background: color_home,
        }
    }]);

    explorerelem.addEventListener('hidden.bs.modal', function (event) {
        // clear up interface, ready for next usage
        dedges.clear();
        dnodes.clear();
    })

    // Now, we go through the old and new traceroute and mark the differences
    // TODO: this is a test implementation
    // This only compares for an exact match on hop number and hostname.
    // Obviously, we need something way more complicated here.
    // Consider this a bad stub implementation
    let lastid = 0; // last identifier added to graph (node id)
    let lastold = 0; // last identifier for new
    let lastnew = 0; // last identifier for old

    function addNode(lastid, parentold, parentnew, item, destination) {
        let label = createNodeLabel(item);
        let color = color_intermediate
        let currentid = lastid + 1;
        if (parentold === parentnew) {
            //shared edge with 1 parent
            color = color_intermediate;
            dedges.add([{from: parentold, to: currentid, color: {color: color}}]);
        }else{
            if (parentold != null) {
                //old edge with 1 parent
                color = color_old;
                dedges.add([{from: parentold, to: currentid, color: {color: color}}]);
            }
            if (parentnew != null) {
                //new edge with 1 parent
                color = color_new;
                dedges.add([{from: parentnew, to: currentid, color: {color: color}}]);
            }
            if (parentold != null && parentnew != null) {
                //new node is shared so set neutral color
                color = color_intermediate
            }
        }
        //console.log(item)
        if (destination == item.ip){
            label = createNodeLabel(item, true);
            color = color_destination;
        }
        dnodes.add([{id: currentid, label: label, ip: item.ip, color: { background: color }}]);
        return currentid
    };

    const destination = histitem.destination;
    const max_elements = Math.max(histitem.old.length, histitem.new.length);
    const min_elements = Math.min(histitem.old.length, histitem.new.length);
    Array(max_elements).fill(true).forEach(function (_true, index) {
        if (index < min_elements && histitem.old[index].ip == histitem.new[index].ip) {
            // shared node
            lastid = lastold = lastnew = addNode(lastid, lastold, lastnew, histitem.old[index], destination);
        } else {
            // OLD node
            if (index < histitem.old.length) {
                lastid = lastold = addNode(lastid, lastold, null, histitem.old[index], destination);
            }
            // NEW node
            if (index < histitem.new.length) {
                lastid = lastnew = addNode(lastid, null, lastnew, histitem.new[index], destination);
            }
        }
    });

    visNetwork.stopSimulation();




}
window.historyClick = historyClick; // make function accessible outside module


function activateRoutingButton(via) { // make route change visible in UI
    switch (via){
        case "btn_router1":
            document.getElementById("btn_router2").classList.remove('active');
            document.getElementById("btn_router1").classList.add('active');
            break;
        case "btn_router2":
            document.getElementById("btn_router1").classList.remove('active');
            document.getElementById("btn_router2").classList.add('active');
            break;
        case "btn_uplink1":
            document.getElementById("btn_uplink2").classList.remove('active');
            document.getElementById("btn_uplink1").classList.add('active');
            break;
        case "btn_uplink2":
            document.getElementById("btn_uplink1").classList.remove('active');
            document.getElementById("btn_uplink2").classList.add('active');
            break;
    }
}

function routingClick(elem) { //onlclick handler for when route change button is pressed
    var url = 'http://10.0.0.1:8080/switch'
    switch(elem.id) {
        case "btn_router1":
            url = url + '/downlink/router1';
            break;
        case "btn_router2":
            url = url + '/downlink/router2';
            break;
        case "btn_uplink1":
            url = url + '/router3/uplink1';
            break;
        case "btn_uplink2":
            url = url + '/router3/uplink2';
            break;
    }

    fetch(url)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                console.log(`The uplink of ${data.device} is now ${data.via}`);
                activateRoutingButton(`btn_${data.via}`);
            }else{
                console.error(`Failed to set uplink of ${data.device} to ${data.via}`);
            }
        })
        .catch(error => console.error('error' + error));
}

window.routingClick = routingClick; // make function accessible outside module

// Show some sample graph
document.addEventListener("DOMContentLoaded", function(event) {
    init(); // Initialise graph
    showTab(document.getElementById('show-control-tab-button'), 'controls')
    showTab(document.getElementById('show-control-tab-button'), 'history')

    startConnection(); // open websocket connection

    $('#show-current-destinations-only').on('click', () => {
        filterDestinations = [];
        networkviz.visNetwork.getSelectedNodes().forEach((node_id) => {
            let node = networkviz.nodes.get(node_id);
            if (node) {
                filterDestinations = filterDestinations.concat(node.destinations);
                networkviz.updateFilterDestinations();
                $('#show-all-destinations').removeAttr('disabled');
            }
        })
    })

    $('#set-notification-destinations').on('click', () => {
        Notification.requestPermission().then((result) => {
          console.log(`notification permissions ${result}`);
        });
        networkviz.visNetwork.getSelectedNodes().forEach((node_id) => {
            let node = networkviz.nodes.get(node_id);
            if (node) {
                notifyChanges = notifyChanges.concat(node.destinations);
                $('#clear-notification-destinations').removeAttr('disabled');
            }
        })
        console.log(`sending notifications for:`, notifyChanges);
    })

    $('#clear-notification-destinations').on('click', () => {
        notifyChanges = [];
        $('#clear-notification-destinations').attr('disabled', true);
    })

    $('#filter-destination-by-port').on('change', (e) => {
        filterDestinations = [];
        let port = e.target.value;
        let destinations = networkviz.nodes.get()
        destinations = destinations.filter(node => {
                if (node.dports) {
                    return node.dports.includes(port.toString());
                }
                return true
            });
        filterDestinations = destinations.map(node => node.ip);
        $('#show-all-destinations').removeAttr('disabled');
        networkviz.updateFilterDestinations();
    })

    $('#show-all-destinations').on('click', () => {
        filterDestinations = [];
        networkviz.updateFilterDestinations();
        $('#show-all-destinations').attr('disabled', true);
        document.getElementById('filter-destination-by-port').value="none";
    })

    $('#asn-mode-switch').on('change', (event) => {
        ASNView = event.target.checked;
        networkviz.setASNMode();
    });

    $('#redraw-network').on('click', () => {
        networkviz.fullRedraw();
    });

    // update visualisation
    networkviz.redraw();

    //Finally, enable all pop-overs (bootstrap)
    // TODO in some way, after adding a node, we need to make sure the popover is enabled.
    // TODO and when a node is removed, do we need to remove the popover?
    // var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    // var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
    //   return new bootstrap.Popover(popoverTriggerEl)
    // });
});
