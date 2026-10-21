import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class Extension implements BurpExtension // BurpExtension là 1 Interface, khi nạp
    //file JAR vào Burp, Burp sẽ quét các class, thấy class Extension có implements là BurpExtension
    //--> class này là một extension sẽ gọi hàm initialize của nó để khởi động
{
    @Override
    public void initialize(MontoyaApi montoyaApi) // hàm này tên là initialize, burp sẽ tự gọi hàm này khi nó nạp extension
    { //tham số truyền vào là monotoyaApi với kiểu dữ liệu(class) là MonotoyaApi
        // Bước 3: Đặt tên
        montoyaApi.extension().setName("My first extension");

        // Bước 4: Context Menu
        montoyaApi.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider()
                // Lấy bộ quản lý giao diện của Burp, đăng ký một đối tượng ẩn danh (class không tên) để làm menu chuột phải.

        {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event)
            {
                JMenuItem menuItem = new JMenuItem("My first context menu");
                menuItem.addActionListener(l -> {
                    montoyaApi.logging().logToOutput("Hello, world!");
                });

                return List.of(menuItem);]
                // Hàm được Burp tự động gọi khi mở menu chuột phải: Tạo một nút menu mới,
                // gắn sự kiện click (in ra chữ Hello) và trả về danh sách các nút cho Burp vẽ lên.
            }
        });

        // Bước 5: Custom Tab
        // Tạo một khung giao diện (JPanel), nhét một dòng chữ (JLabel) vào,
        // sau đó đăng ký khung này thành một Tab mới trên thanh công cụ của Burp.
        JPanel panel = new JPanel();
        panel.add(new JLabel("Hello, world!"));
        montoyaApi.userInterface().registerSuiteTab("My extension tab", panel);
    }
}