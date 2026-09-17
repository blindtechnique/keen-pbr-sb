# Input is iptables-save, never shell/config text. Output is a --noflush
# restore transaction touching only our tagged rules and our reply chain.
# Keep the vendor's interface, mark, port, queue and preceding policy RETURNs.
BEGIN {
    reply_chain = "KpbrNfqTcpReply"
    reply_tag = "keen-pbr-sb:nfqws:tcp-reply:v1"
    input_shortcut_match = "-m state --state RELATED,ESTABLISHED -m connndmmark ! --mark 0x20/0x20"
}
function owned_reply(line) {
    return line ~ /--comment "?keen-pbr-sb:nfqws:tcp-reply:v1"?( |$)/
}
function keenetic_input_shortcut(line) {
    # Revision-1 bytes verified on Keenetic: u32 {0x20, 0x20, 1}. The private
    # xtables adapter preserves mask AND inversion. Do not clone Entware's
    # lossy revision-0 rendering (--mark 0x20/0x0) or a generic ACCEPT rule.
    return line == "-A INPUT " input_shortcut_match " -j ACCEPT"
}
function reply_copy(line) {
    sub(/^-A nfqws_pre /, "-A " reply_chain " ", line)
    sub(/ -j /, " -m comment --comment \"" reply_tag "\" -j ", line)
    return line
}
# Only address-independent, read-only vendor exclusions can be evaluated
# after reverse NAT. Never copy an unknown target, address test or side effect.
function reply_policy(    i, token, module) {
    if (value("-j") != "RETURN" || value("-i") !~ /^[a-zA-Z0-9_.:-]+$/ || length(value("-i")) > 15) return 0
    if (value("--mark") !~ /^0x[0-9a-fA-F]+\/0x[0-9a-fA-F]+$/) return 0
    delete policy_seen
    for (i = 3; i <= NF; i++) {
        token = $i
        if (policy_seen[token]++) return 0
        if (token == "-m") {
            module = $(++i)
            if (module != "mark" && module != "connmark") return 0
        } else if (token == "!") {
            if ($(i + 1) != "--mark") return 0
        } else if (token == "-i" || token == "--mark" || token == "-j") i++
        else return 0
    }
    return policy_seen["-m"] && policy_seen["-i"] && policy_seen["--mark"]
}
function reply_control(    i, token, flags, flag_value) {
    if (value("-i") !~ /^[a-zA-Z0-9_.:-]+$/ || length(value("-i")) > 15 || !valid_ports(value("--sports"))) return 0
    if (value("--mark") !~ /^0x[0-9a-fA-F]+\/0x[0-9a-fA-F]+$/ || value("--queue-num") != queue) return 0
    delete control_seen
    for (i = 3; i <= NF; i++) {
        token = $i
        if (token == "-m") {
            token = $(++i)
            if (token != "tcp" && token != "mark" && token != "multiport") return 0
            if (control_seen["module:" token]++) return 0
        } else {
            if (control_seen[token]++) return 0
            if (token == "!") {
                if ($(i + 1) != "--mark") return 0
            } else if (token == "--tcp-flags") {
                flags = $(++i); flag_value = $(++i)
                if (flags != flag_value || (flags != "FIN" && flags != "RST" && flags != "SYN,ACK")) return 0
            } else if (token == "--queue-bypass") continue
            else if (token == "-i" || token == "--sports" || token == "-p" || token == "--mark" || token == "-j" || token == "--queue-num") i++
            else return 0
        }
    }
    return control_seen["!"] && control_seen["--queue-bypass"] && control_seen["--tcp-flags"] && control_seen["module:mark"] && control_seen["module:multiport"]
}
function want_reply(line,    fields) {
    reply_wanted[++reply_wanted_count] = line
    split(line, fields, " ")
    reply_wanted_order[fields[2]] = reply_wanted_order[fields[2]] line "\n"
}
function delete_rule(line) { sub(/^-A /, "-D ", line); print line }
function owned(line) {
    return line ~ /--comment "?keen-pbr-sb:nfqws:tcp-window:v1"?( |$)/
}
function value(flag,    i) {
    for (i = 3; i < NF; i++) if ($i == flag) return $(i + 1)
    return ""
}
function valid_ports(ports,    count, p, r, i, n) {
    count = split(ports, p, ",")
    n = 0
    for (i = 1; i <= count; i++) {
        if (p[i] !~ /^[0-9]+(:[0-9]+)?$/) return 0
        n += split(p[i], r, ":")
        if (r[1] < 1 || r[1] > 65535) return 0
        if (index(p[i], ":") && (r[2] < r[1] || r[2] > 65535)) return 0
    }
    return count > 0 && n <= 15
}
function template(    i, token, iface, ports, mark, count, n, fields, dir, iflag, pflag, rule) {
    dir = $2 == "nfqws_pre" ? "reply" : "original"
    iflag = $2 == "nfqws_pre" ? "-i" : "-o"
    pflag = $2 == "nfqws_pre" ? "--sports" : "--dports"
    iface = value(iflag); ports = value(pflag); mark = value("--mark")
    if (iface !~ /^[a-zA-Z0-9_.:-]+$/ || length(iface) > 15 || !valid_ports(ports)) return ""
    if (mark !~ /^0x[0-9a-fA-F]+\/0x[0-9a-fA-F]+$/) return ""
    if (value("--queue-num") != queue || value("--connbytes-mode") != "packets" || value("--connbytes-dir") != dir) return ""
    count = value("--connbytes")
    if (count !~ /^1:[0-9]+$/) return ""
    split(count, fields, ":"); n = fields[2] + 0
    if (n < 1 || n > 65535) return ""
    # A finite grammar, including the negated processed-mark match. Unknown
    # upstream selectors disable this extension rather than broadening it.
    delete seen
    for (i = 3; i <= NF; i++) {
        token = $i
        if (token == "-m") {
            token = $(++i)
            if (token != "tcp" && token != "mark" && token != "multiport" && token != "connbytes") return ""
            if (seen["module:" token]++) return ""
        } else if (token == "!") {
            if ($(i + 1) != "--mark" || seen["!"]++) return ""
        } else if (token == "--queue-bypass") {
            if (seen[token]++) return ""
        } else if (token == iflag || token == pflag || token == "-p" || token == "--mark" || token == "--connbytes" || token == "--connbytes-mode" || token == "--connbytes-dir" || token == "-j" || token == "--queue-num") {
            if (seen[token]++) return ""
            i++
        } else return ""
    }
    if (!seen["!"] || !seen["--queue-bypass"] || !seen["module:mark"] || !seen["module:connbytes"] || !seen["module:multiport"]) return ""
    if (templates[$0]++) return ""
    parents[$2]++
    if (parents[$2] > 16) return ""
    if (n >= budget) return "covered"
    # Canonical iptables-save order, with SYN/FIN/RST excluded: stock handles
    # those outside its packet window already. Never queue a packet twice.
    rule = "-A " $2 " " iflag " " iface " -p tcp -m tcp --tcp-flags FIN,SYN,RST NONE -m mark ! --mark " mark
    rule = rule " -m multiport " pflag " " ports " -m connbytes --connbytes " (n + 1) ":" budget " --connbytes-mode packets --connbytes-dir " dir
    return rule " -m comment --comment \"keen-pbr-sb:nfqws:tcp-window:v1\" -j NFQUEUE --queue-num " queue " --queue-bypass"
}
$1 == ":KpbrNfqTcpReply" { reply_exists = 1 }
$1 == "-A" {
    if ($2 == "nfqws_pre") pre_position++
    if (owned_reply($0)) {
        reply_old[++reply_old_count] = $0
        reply_old_order[$2] = reply_old_order[$2] $0 "\n"
        if ($2 == "nfqws_pre" && pre_position != 1) reply_misplaced = 1
        if ($2 == "INPUT") input_old_before[++input_old_count] = input_rules
        next
    }
    if ($2 == "INPUT") {
        input_rules++
        if ($0 == "-A INPUT -m state --state RELATED,ESTABLISHED -m connndmmark --mark 0x20/0x0 -j ACCEPT") reply_bad = 1
        if (keenetic_input_shortcut($0)) {
            input_shortcuts++
            input_shortcut_position = input_rules
        }
    }
    if ($2 == reply_chain || value("-j") == reply_chain || value("-g") == reply_chain) reply_foreign = 1
    if (value("-j") == "nfqws_pre" || value("-g") == "nfqws_pre") {
        pre_hooks++
        if ($0 != "-A PREROUTING -j nfqws_pre") reply_bad = 1
    }
}
($1 == "-A" && ($2 == "nfqws_pre" || $2 == "nfqws_post")) {
    if (owned($0)) { old[++old_count] = $0; next }
    if ($2 == "nfqws_pre") {
        if (value("-j") == "RETURN") {
            if (!reply_policy()) reply_bad = 1
            else reply_source[++reply_source_count] = reply_copy($0)
        } else if (value("-j") == "NFQUEUE" && value("-p") == "tcp") {
            if (value("--connbytes") == "" && !reply_control()) reply_bad = 1
            reply_source[++reply_source_count] = reply_copy($0)
        } else if (!(value("-j") == "NFQUEUE" && value("-p") == "udp")) reply_bad = 1
    }
    if (value("-j") != "NFQUEUE") next
    if (value("-p") == "udp") next
    if (value("-p") != "tcp") { incompatible = 1; next }
    if (value("--connbytes") != "") {
        rule = template()
        if (rule == "") incompatible = 1
        else if (rule != "covered") wanted[++wanted_count] = rule
    } else {
        # The only unbounded stock TCP rules are FIN, RST and SYN+ACK.
        flags = value("--tcp-flags")
        flags_value = ""
        for (i = 3; i < NF - 1; i++) if ($i == "--tcp-flags") flags_value = $(i + 2)
        if (!((flags == "FIN" || flags == "RST" || flags == "SYN,ACK") && flags == flags_value)) incompatible = 1
    }
}
END {
    if (mode != "apply" || incompatible || !parents["nfqws_pre"] || !parents["nfqws_post"]) wanted_count = 0
    reply_enabled = mode == "apply" && reply == "postnat_v1" && !incompatible && !reply_bad && !reply_foreign && parents["nfqws_pre"] && parents["nfqws_post"] && pre_hooks == 1
    # An existing, untagged chain with our name is not ours to claim/flush.
    if (reply_exists && !reply_old_count) reply_enabled = 0
    if (reply_enabled) {
        for (i = 1; i <= reply_source_count; i++) want_reply(reply_source[i])
        retained = 0
        for (i = 1; i <= wanted_count; i++) {
            if (wanted[i] ~ /^-A nfqws_pre /) {
                line = wanted[i]
                sub(/^-A nfqws_pre /, "-A " reply_chain " ", line)
                sub(/keen-pbr-sb:nfqws:tcp-window:v1/, reply_tag, line)
                want_reply(line)
            } else wanted[++retained] = wanted[i]
        }
        wanted_count = retained
        if (input_shortcuts == 1) {
            # NFQUEUE acceptance ends this mangle hook. Match exactly the
            # native shortcut so a nonmatching packet cannot skip later
            # policy; those packets can reach our ordinary tail hook.
            input_fast_hook = "-A INPUT -p tcp " input_shortcut_match " -m comment --comment \"" reply_tag "\" -j " reply_chain
            want_reply(input_fast_hook)
        }
        want_reply("-A INPUT -p tcp -m comment --comment \"" reply_tag "\" -j " reply_chain)
        want_reply("-A FORWARD -p tcp -m comment --comment \"" reply_tag "\" -j " reply_chain)
        want_reply("-A nfqws_pre -p tcp -m comment --comment \"" reply_tag "\" -j RETURN")
    }
    same = old_count == wanted_count
    for (i = 1; same && i <= old_count; i++) if (old[i] != wanted[i]) same = 0
    if (reply_old_count != reply_wanted_count || reply_misplaced) same = 0
    # Count only non-owned INPUT rules: the transaction deletes our old hook
    # before inserting it. Repair the old appended hook or a native reorder,
    # even when every owned rule's text is already identical. Unknown or
    # ambiguous native policy retains conservative append placement.
    input_wanted_count = input_shortcuts == 1 ? 2 : 1
    if (reply_enabled) {
        if (input_old_count != input_wanted_count || input_old_before[input_old_count] != input_rules) same = 0
        if (input_shortcuts == 1 && input_old_before[1] != input_shortcut_position - 1) same = 0
    }
    for (chain in reply_old_order) if (reply_old_order[chain] != reply_wanted_order[chain]) same = 0
    for (chain in reply_wanted_order) if (reply_old_order[chain] != reply_wanted_order[chain]) same = 0
    if (same) exit
    print "*mangle"
    for (i = 1; i <= old_count; i++) delete_rule(old[i])
    for (i = 1; i <= reply_old_count; i++) delete_rule(reply_old[i])
    if (reply_enabled && !reply_exists) print "-N " reply_chain
    if (!reply_enabled && reply_exists && reply_old_count && !reply_foreign) print "-X " reply_chain
    for (i = 1; i <= wanted_count; i++) print wanted[i]
    for (i = 1; i <= reply_wanted_count; i++) {
        line = reply_wanted[i]
        # Suppress TCP only in the old, pre-DNAT entry. All original vendor
        # rules remain byte-for-byte; their read-only TCP policy is copied to
        # INPUT/FORWARD. UDP keeps the original chain and its original hook.
        sub(/^-A nfqws_pre /, "-I nfqws_pre 1 ", line)
        # Observe router replies before the recognized native fast ACCEPT;
        # all rules preceding that anchor stay ahead of our observation.
        if (line == input_fast_hook) sub(/^-A INPUT /, "-I INPUT " input_shortcut_position " ", line)
        print line
    }
    print "COMMIT"
}
