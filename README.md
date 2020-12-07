# RSA大礼包
实验摘要：
RSA 密码算法是使用最为广泛的公钥密码体制。选择 5 个参数：两个素数𝑝和𝑞、模数𝑁 = 𝑝𝑞、加密指数𝑒和解密指数𝑑。设𝑚为待加密消息，RSA 体制破译相当于已知𝑚𝑒 mod 𝑁，能否还原𝑚的数论问题。
有人制作了一个 RSA 加解密软件。Alice 使用该软件发送了一个通关密语，且所有加密数据已经被截获。实验目的为仅从加密数据恢复通关密语及 RSA 体制参数。并给出原文和参数。如果不能则给出已恢复部分并说明剩余部分不能恢复的理由。
将实验步骤分为以下三部分：
一、从帧中得到公钥和密文
二、确定密文的解密方法并解密
三、对解密明文进行整理

通过以上常规的RSA破解方法，得到了一些明文片段:
Frame0:My secre
Frame1:.Imagin
Frame2: That is
Frame3:t is a f
Frame4:My secre
Frame6: ”Logic
Frame8:t is a f
Frame10:will get
Frame12:t is a f
Frame16:t is a f
Frame18:m A to B
Frame19:instein.
Frame20:t is a f
