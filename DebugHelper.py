import base64
import binascii

import ida_dbg
import ida_idaapi
import ida_kernwin
import ida_segment
import idaapi
import idautils
import idc


class MenuContext(idaapi.action_handler_t):

    @classmethod
    def get_name(self):
        return self.__name__

    @classmethod
    def get_label(self):
        return self.label

    @classmethod
    def register(self, plugin, label):
        self.plugin = plugin
        self.label = label
        instance = self()
        return idaapi.register_action(idaapi.action_desc_t(
            self.get_name(),  # Name. Acts as an ID. Must be unique.
            instance.get_label(),  # Label. That's what users see.
            instance  # Handler. Called when activated, and for updating
        ))

    @classmethod
    def unregister(self):
        """Unregister the action.
        After unregistering the class cannot be used.
        """
        idaapi.unregister_action(self.get_name())

    @classmethod
    def activate(self, ctx):
        # dummy method
        return 1

    @classmethod
    def update(self, ctx):
        try:
            if ctx.widget_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_FORM
            else:
                return idaapi.AST_DISABLE_FOR_FORM
        except Exception as e:
            # Add exception for main menu on >= IDA 7.0
            return idaapi.AST_ENABLE_ALWAYS


class JumpToHexView(MenuContext):
    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        for i in range(1, 10):
            title = "Hex View-%d" % i
            widget = ida_kernwin.find_widget(title)
            if widget is not None:
                ida_kernwin.activate_widget(widget, True)
                ida_kernwin.jumpto(ea)
                return 1
        idaapi.warning("No Hex View Found")
        return 1


class RVAJumpForm(idaapi.Form):
    def __init__(self, module_address):
        template = r"""STARTITEM 0
BUTTON YES* Jump
Jump without rebase the idb.

                {FormChangeCb}
                <module address:{module_address}>
                <offset address:{offset_address}>
                """
        super(RVAJumpForm, self).__init__(template, {
            'FormChangeCb': self.FormChangeCb(self.OnFormChange),
            'module_address': self.NumericInput(value=module_address, swidth=40, tp=self.FT_HEX),
            'offset_address': self.NumericInput(value=0, swidth=40, tp=self.FT_HEX),
        })
        self.Compile()

    def OnFormChange(self, fid):
        return 1


class RVAJumpMenu(MenuContext):
    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        for mod in idautils.Modules():
            if mod.base <= ea <= (mod.base + mod.size):
                form = RVAJumpForm(mod.base)
                if form.Execute() == 1:
                    base_addr = form.module_address.value
                    offset = form.offset_address.value
                    ida_kernwin.jumpto(base_addr + offset)
                    form.Free()
                    return 1
                form.Free()
        return 1


class DumpMemoryForm(idaapi.Form):
    def __init__(self, module_address):
        template = r"""STARTITEM 0
BUTTON YES* Dump
dump memory to file

                {FormChangeCb}
                <start address:{start_address}>
                <end   address:{end_address}>
                <dump     size:{dump_size}>
                """
        super(DumpMemoryForm, self).__init__(template, {
            'FormChangeCb': self.FormChangeCb(self.OnFormChange),
            'start_address': self.NumericInput(value=module_address, tp=self.FT_HEX,swidth=40),
            'end_address': self.NumericInput(value=0, tp=self.FT_HEX,swidth=40),
            'dump_size': self.NumericInput(value=0, tp=self.FT_HEX,swidth=40),
        })
        self.Compile()

    def OnFormChange(self, fid):
        return 1



class DumpMemu(MenuContext):
    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        form = DumpMemoryForm(ea)
        if form.Execute() == 1:
            file_path = ida_kernwin.ask_file(True, "*.dump", "please select dump file to save")
            if not file_path:
                ida_kernwin.warning("dump file path is empty")
                form.Free()
                return 1
            end_address = form.end_address.value
            dump_size = form.dump_size.value
            if dump_size <= 0 and end_address <= 0:
                ida_kernwin.warning("size is empty")
                form.Free()
                return 1
            start_address = form.start_address.value
            if end_address > 0 and end_address > start_address:
                bytes_data = idc.get_bytes(start_address, end_address - start_address, idaapi.is_debugger_on())
                if bytes_data:
                    with open(file_path, "wb") as f:
                        f.write(bytes_data)
                    ida_kernwin.msg("dump success")
                else:
                    ida_kernwin.warning("dump failed")
            elif dump_size > 0:
                bytes_data = idc.get_bytes(start_address, dump_size, idaapi.is_debugger_on())
                if bytes_data:
                    with open(file_path, "wb") as f:
                        f.write(bytes_data)
                    ida_kernwin.msg("dump success")
                else:
                    ida_kernwin.warning("dump failed")
        form.Free()
        return 1


class WriteMemoryForm(idaapi.Form):
    def __init__(self, target_address):
        template = r"""STARTITEM 0
BUTTON YES* Write
Write to Memory

{FormChangeCb}
<Target address : {target_address}>
<Write Hex Data:{hex_data}><Write Base64 Data:{base64_data}><Write ASCII Data:{ascii_data}>{data_type}>
<Input data: {input_data} >
"""
        super(WriteMemoryForm, self).__init__(template, {
            'FormChangeCb': self.FormChangeCb(self.OnFormChange),
            'target_address': self.StringInput(value="0x{:x}".format(target_address)),
            'data_type': idaapi.Form.RadGroupControl({"hex_data", "base64_data", "ascii_data"}, value=0),
            'input_data': idaapi.Form.MultiLineTextControl(text="", swidth=60)
        })
        self.Compile()

    def OnFormChange(self, fid):
        # if fid == self.data_type.id:
        #     print("data type changed:", self.GetControlValue(self.data_type))
        return 1


class WriteMemoryData(MenuContext):
    def activate(self, ctx):
        ea = idc.get_screen_ea()
        form = WriteMemoryForm(ea)
        if form.Execute() == 1:
            data_type = form.data_type.value
            string_data = form.input_data.value
            target_address = int(form.target_address.value, 16)
            if string_data is None or len(string_data) <= 0:
                ida_kernwin.warning("input data is empty")
                form.Free()
                return 1
            if target_address <= 0:
                ida_kernwin.warning("target address is empty")
                form.Free()
                return 1
            string_data = string_data.strip()
            stop_words = [",", "0x", "0X", "{", "}", "H", "h", "[", "]", " ", "\n", "\r" ";"]
            for ch in stop_words:
                string_data = string_data.replace(ch, "")

            if data_type == 0:
                if len(string_data) % 2 != 0:
                    ida_kernwin.warning("hex data length must be even")
                    form.Free()
                    return 1
                else:
                    hex_data = string_data
                    write_addr = target_address
                    try:
                        hex_data = bytearray(binascii.a2b_hex(hex_data))
                        for i in range(len(hex_data)):
                            idaapi.patch_byte(write_addr + i, hex_data[i])
                        print("write success")
                    except:
                        ida_kernwin.warning("write failed")

            elif data_type == 1:
                try:
                    base64_data = bytearray(base64.b64decode(string_data))
                    write_addr = target_address
                    for i in range(len(base64_data)):
                        idaapi.patch_byte(write_addr + i, base64_data[i])
                    print("write success")
                except:
                    ida_kernwin.warning("write failed")
            elif data_type == 2:
                try:
                    ascii_data = bytearray(string_data.encode('utf-8'))
                    write_addr = target_address
                    for i in range(len(ascii_data)):
                        idaapi.patch_byte(write_addr + i, ascii_data[i])
                    print("write success")
                except:
                    ida_kernwin.warning("write failed")
        return 1


class CopyMemoryForm(idaapi.Form):
    def __init__(self, target_address):
        self
        template = r"""STARTITEM 0
BUTTON YES* OK
Copy From Memory

{FormChangeCb}
<Target address : {target_address}>
<Data    length :{data_length}>
<Copy Hex Data:{hex_data}><Copy Base64 Data:{base64_data}><Copy ASCII Data:{string_data}>{data_type}>
<Out data: {input_data} >
<Copy Data:{copy_data}>
"""
        super(CopyMemoryForm, self).__init__(template, {
            'FormChangeCb': self.FormChangeCb(self.OnFormChange),
            'target_address': self.StringInput(value="0x{:x}".format(target_address)),
            'data_length': self.StringInput(value="0xf"),
            'data_type': idaapi.Form.RadGroupControl({"hex_data", "base64_data", "string_data"}, value=0),
            'input_data': idaapi.Form.StringInput(value="123", swidth=50),
            'copy_data': idaapi.Form.ButtonInput(handler=self.OnCopyButtonClick, swidth=60)
        })
        self.Compile()

    def OnCopyButtonClick(self, code=0):
        data_type_value = self.GetControlValue(self.data_type)
        dump_address = self.get_copy_address()
        length = self.get_data_length()
        if length <= 0 or dump_address <= 0:
            ida_kernwin.warning("address is invalid")
            return
        if not self.is_address_readable(dump_address) or not self.is_address_readable(dump_address + length):
            ida_kernwin.warning("address is not readable", hex(dump_address), "-", hex(dump_address + length))
            return
        if data_type_value == 0:
            read_bytes = idc.get_bytes(dump_address, length, ida_dbg.is_debugger_on())
            hex_str = str(binascii.hexlify(read_bytes).decode('utf-8'))
            self.SetControlValue(self.input_data, hex_str)
            return
        elif data_type_value == 1:
            read_bytes = idc.get_bytes(dump_address, length, ida_dbg.is_debugger_on())
            base64_str = base64.b64encode(read_bytes).decode('utf-8')
            self.SetControlValue(self.input_data, base64_str)
        elif data_type_value == 2:
            self.EnableField(self.data_length, False)
            temp_address = dump_address
            read_bytes = bytearray()
            while True:
                read_byte = idc.get_bytes(temp_address, 1, ida_dbg.is_debugger_on())
                if read_byte == b"\x00":
                    break
                temp_address += 1
                read_bytes += read_byte
            ascii_str = read_bytes.decode('utf-8')
            self.SetControlValue(self.input_data, ascii_str)

    def get_data_length(self):
        length = self.GetControlValue(self.data_length)
        length = length.strip()
        stop_words = [",", "0x", "0X", "{", "}", "H", "h", "[", "]", " ", "\n", "\r" ";"]
        for ch in stop_words:
            length = length.replace(ch, "")
        try:
            length = int(length, 16)
            if length <= 0:
                return 16
            if length > 1000:
                return 1000
            return length
        except:
            pass
        return 16

    def get_copy_address(self):
        address = self.GetControlValue(self.target_address)
        address = address.strip()
        try:
            stop_words = [",", "0x", "0X", "{", "}", "H", "h", "[", "]", " ", "\n", "\r" ";"]
            for ch in stop_words:
                address = address.replace(ch, "")
            address = int(address, 16)
            if address <= 0:
                return 0
            return address
        except:
            pass
        return 0

    def is_address_readable(self, address):
        # 获取地址所在的段
        seg = ida_segment.getseg(address)
        if seg is None:
            return False
        if seg.perm & ida_segment.SEGPERM_READ:
            return True
        else:
            return False

    def OnFormChange(self, fid):
        self._is_processing = True
        if fid == self.data_type.id:
            if self.GetControlValue(self.data_type) == 2:
                self.EnableField(self.data_length, False)
            else:
                self.EnableField(self.data_length, True)

        return 1



class CopyMemoryData(MenuContext):
    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        if ea == idaapi.BADADDR:
            ida_kernwin.warning("address is invalid")
            return 1
        form = CopyMemoryForm(ea)
        if form.Execute() == 1:
            form.Execute()
            form.Free()
        return 1


class DebuggerUiHook(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        if not ida_dbg.is_debugger_on():
            return

        if idaapi.IDA_SDK_VERSION >= 900:
            dump_type = idaapi.BWN_HEXVIEW
        else:
            dump_type = idaapi.BWN_DUMP

        if ida_kernwin.get_widget_type(form) == idaapi.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(form, popup, JumpToHexView.get_name())
            ida_kernwin.attach_action_to_popup(form, popup, RVAJumpMenu.get_name())
        elif ida_kernwin.get_widget_type(form) == dump_type:
            ida_kernwin.attach_action_to_popup(form, popup, DumpMemu.get_name())
            ida_kernwin.attach_action_to_popup(form, popup, WriteMemoryData.get_name())
            ida_kernwin.attach_action_to_popup(form, popup, CopyMemoryData.get_name())


class IdaDebuggerPlugin(ida_idaapi.plugin_t):
    comment = "IDA Debugger Helper plugin"
    wanted_name = "IdaDebugger"
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        try:
            DumpMemu.register(self, "Dump Data")
            WriteMemoryData.register(self, "Write Data")
            CopyMemoryData.register(self, "Copy Data")
            JumpToHexView.register(self, "Sync HexView")
            RVAJumpMenu.register(self, "RVA Jump")
        except:
            pass
        self.popup_ui_hook = DebuggerUiHook()
        self.popup_ui_hook.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if self.popup_ui_hook is not None:
            self.popup_ui_hook.unhook()
            self.popup_ui_hook = None


def PLUGIN_ENTRY():
    return IdaDebuggerPlugin()
