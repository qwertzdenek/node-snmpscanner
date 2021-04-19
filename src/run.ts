import {AppConstants} from "./API/AppConstants";
import {Netmask} from "netmask";
import { Session as snmpSession } from "snmp-native";

const ping = require('net-ping');
import EventEmitter = require('events');
import { createBrotliCompress } from "zlib";


class App {

    public static getNetmask(): Netmask {
        const cidr = process.argv[2];

        if (cidr) {
            return new Netmask(cidr)
        } else {
            return null
        }
    }

    public pingNet(netmask: Netmask, timeout: number = 3000, retries: number = 0): EventEmitter {
        const targets: string[] = [];

        const emitter = new EventEmitter();
        const session = ping.createSession({timeout, retries});
        netmask.forEach((ip: string) => {
            session.pingHost (ip, function (error: Error, target: string) {
                if (error) {
                    emitter.emit("error", target, error);
                } else {
                    emitter.emit("found", target);
                }
                if (netmask.last === ip) {
                    session.close();
                }
            });
        });
        return emitter;
    }

    public scanAndPrint() {
        const netmask = App.getNetmask();
        if (netmask) {
            const session: snmpSession = new snmpSession();
            const pingEmitter = this.pingNet(netmask);

            let processed = 0;
            const evaluateProcessed = function () {
                if (++processed >= netmask.size-2) {
                    session.close();
                }
            }

            const hostnameOID = AppConstants.SNMP_NAME.split(".").map((o) => parseInt(o));
            const nicIndexesOID = AppConstants.SNMP_NIC_INDEXES.split(".").map((o) => parseInt(o));
            const nicNameOID = AppConstants.SNMP_NIC_NAMES.split(".").map((o) => parseInt(o));

            pingEmitter.on("found", function (target) {
                session.get({
                    oid: hostnameOID,
                    host: target
                }, function (error, varbinds) {
                    if (!error && varbinds.length > 0) {
                        const hostname = varbinds[0].value;
                        session.getSubtree({
                            oid: nicIndexesOID,
                            host: target
                        }, function (error, varbinds) {
                            if (!error && varbinds.length > 0) {
                                const indexes = varbinds.map(vb => vb.value);
                                session.getAll({
                                    oids: indexes.map(index => [...nicNameOID, parseInt(index)]),
                                    host: target
                                }, function (error, varbinds) {
                                    if (!error && varbinds.length > 0) {
                                        console.log(`${target}; ${hostname}; ${varbinds.map(vb => vb.value).join("; ")}`);
                                    }
                                    evaluateProcessed();
                                });
                            } else {
                                evaluateProcessed();
                            }
                        });
                    } else {
                        evaluateProcessed();
                    }
                });
            });
            pingEmitter.on("error", function (target, error) {
                evaluateProcessed();
            });
        } else {
            console.log(AppConstants.HELP);
        }
    }
}

new App().scanAndPrint();
